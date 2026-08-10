package ui

import (
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/lvim-tech/keyforge/internal/gpgkeys"
	"github.com/lvim-tech/keyforge/internal/passstore"
)

type storeMode int

const (
	smList    storeMode = iota
	smForm              // adding a new entry, or replacing an existing password
	smMove              // typing a new path for the selected entry
	smConfirm           // about to delete
	smDetail            // an entry's metadata, never its password
	smFilter            // narrowing the list
)

type passView struct {
	entries []passstore.Entry
	shown   []passstore.Entry // entries after the filter
	sel     int
	loaded  bool
	err     string

	// The state of the store's master password: the passphrase on the GPG key everything here is
	// encrypted to. It is loaded with the list because it is the first thing worth knowing about a
	// password store and the last thing anyone checks.
	prot    gpgkeys.Protection
	protKey string
	ttl     gpgkeys.CacheTTL

	mode   storeMode
	form   *passForm
	move   input
	filter input

	// The detail pane, decrypted once when it is opened and laid out on every draw. Splitting it
	// this way is not an optimisation: building it in Render would run gpg on every keystroke.
	detailEntry  passstore.Entry
	detailFields map[string]string
	detailErr    string
}

func newPassView() *passView {
	return &passView{
		move:   newInput("new path", "websites/example.com/user"),
		filter: newInput("filter", "part of the path"),
	}
}

func (v *passView) Title() string { return "Passwords" }

func (v *passView) capturesInput() bool {
	return v.mode == smForm || v.mode == smMove || v.mode == smFilter
}

func (v *passView) Init() tea.Cmd { return loadPass }

// passLoaded carries a scan of the store back to the UI thread.
type passLoaded struct {
	entries []passstore.Entry
	prot    gpgkeys.Protection
	protKey string
	ttl     gpgkeys.CacheTTL
	err     error
}

// loadPass reads the store. Names and timestamps only — nothing is decrypted, so opening keyforge
// never makes pinentry appear, and the tab is populated before it is ever looked at.
func loadPass() tea.Msg {
	if !passstore.Available() {
		return passLoaded{err: fmt.Errorf("pass is not installed, or the store is not initialised (pass init <gpg-id>)")}
	}
	entries, err := passstore.Entries()
	prot, key := gpgkeys.StoreProtection(passstore.Recipient())
	return passLoaded{entries: entries, prot: prot, protKey: key, ttl: gpgkeys.AgentCacheTTL(), err: err}
}

func (v *passView) current() (passstore.Entry, bool) {
	if v.sel < 0 || v.sel >= len(v.shown) {
		return passstore.Entry{}, false
	}
	return v.shown[v.sel], true
}

// applyFilter recomputes the visible slice and keeps the cursor inside it.
func (v *passView) applyFilter() {
	q := strings.ToLower(strings.TrimSpace(v.filter.String()))
	if q == "" {
		v.shown = v.entries
	} else {
		v.shown = nil
		for _, e := range v.entries {
			if strings.Contains(strings.ToLower(e.Name), q) {
				v.shown = append(v.shown, e)
			}
		}
	}
	if v.sel >= len(v.shown) {
		v.sel = max(0, len(v.shown)-1)
	}
}

func (v *passView) Update(msg tea.Msg) (view, tea.Cmd) {
	switch msg := msg.(type) {
	case reloadMsg:
		return v, loadPass

	case passLoaded:
		v.loaded = true
		if msg.err != nil {
			v.err = msg.err.Error()
			return v, nil
		}
		v.err, v.entries = "", msg.entries
		v.prot, v.protKey, v.ttl = msg.prot, msg.protKey, msg.ttl
		v.applyFilter()
		return v, nil

	case tea.KeyMsg:
		switch v.mode {
		case smForm:
			return v.updateForm(msg)
		case smMove:
			return v.updateMove(msg)
		case smFilter:
			return v.updateFilter(msg)
		case smConfirm:
			return v.updateConfirm(msg)
		case smDetail:
			switch msg.String() {
			case "esc", "enter", "q":
				v.mode = smList
			}
			return v, nil
		}
		return v.updateList(msg)
	}
	return v, nil
}

func (v *passView) updateList(msg tea.KeyMsg) (view, tea.Cmd) {
	switch msg.String() {
	case "j", "down":
		if v.sel < len(v.shown)-1 {
			v.sel++
		}
	case "k", "up":
		if v.sel > 0 {
			v.sel--
		}
	case "g":
		v.sel = 0
	case "G":
		v.sel = max(0, len(v.shown)-1)

	case "/":
		v.mode = smFilter

	case "r":
		return v, loadPass

	case "a":
		if !passstore.Available() {
			return v, failure("pass is not initialised on this machine")
		}
		// A new entry starts in the folder you are standing in, which is nearly always the one you
		// want — a second login for the same site is the common case, a brand new tree is not.
		folder := ""
		if e, ok := v.current(); ok {
			folder = e.Folder
		}
		v.form = newPassForm(folder)
		v.mode = smForm

	case "e":
		e, ok := v.current()
		if !ok {
			return v, failure("no entry selected")
		}
		// Rewriting the entry replaces the whole file, metadata included, so the old fields are read
		// back first and carried over. That read decrypts, and decryption can fail with the agent
		// locked — in which case the form says so instead of quietly dropping login and url.
		fields, err := passstore.Fields(e.Name)
		readErr := ""
		if err != nil {
			readErr = err.Error()
			fields = map[string]string{}
		}
		v.form = newPassFormReplace(e.Name, fields, readErr)
		v.mode = smForm

	case "c":
		e, ok := v.current()
		if !ok {
			return v, failure("no entry selected")
		}
		// pass decrypts and hands the value straight to the clipboard helper, then clears it again
		// by itself. keyforge never sees the password — which is why there is no "reveal" beside
		// this: it would be strictly more exposure for strictly less use.
		return v, func() tea.Msg {
			return execMsg{
				cmd:  passstore.CopyCmd(e.Name),
				then: fmt.Sprintf("%s is on the clipboard — pass will clear it by itself", e.Leaf),
			}
		}

	case "enter", "f":
		e, ok := v.current()
		if !ok {
			return v, failure("no entry selected")
		}
		// Reading the fields decrypts, so it happens once here — on the keypress — and never in
		// Render, which runs on every redraw and would ask gpg again for each one.
		fields, err := passstore.Fields(e.Name)
		v.detailEntry, v.detailFields, v.detailErr = e, fields, ""
		if err != nil {
			v.detailFields, v.detailErr = nil, err.Error()
		}
		v.mode = smDetail

	case "m":
		e, ok := v.current()
		if !ok {
			return v, failure("no entry selected")
		}
		v.move.set(e.Name)
		v.mode = smMove

	case "d":
		if _, ok := v.current(); !ok {
			return v, failure("no entry selected")
		}
		v.mode = smConfirm

	case "p":
		// The store's master password: the passphrase of the GPG key it encrypts to. Changing it
		// here rather than sending the user to gpg is the point of the tab knowing about it at all.
		if v.protKey == "" {
			return v, failure("could not find the store's GPG key")
		}
		return v, func() tea.Msg {
			return execMsg{
				cmd:  gpgkeys.ChangePassphraseCmd(v.protKey),
				then: "the store's password has been changed — it unlocks every entry here",
			}
		}
	}
	return v, nil
}

func (v *passView) updateForm(msg tea.KeyMsg) (view, tea.Cmd) {
	switch msg.String() {
	case "esc":
		v.form.close()
		v.form = nil
		v.mode = smList
		return v, nil
	case "enter":
		name, err := v.form.submit()
		if err != nil {
			return v, failure("%v", err)
		}
		v.form.close()
		v.form = nil
		v.mode = smList
		return v, tea.Batch(status("stored in pass as %s", name), reload)
	}
	if cmd := v.form.update(msg); cmd != nil {
		return v, cmd
	}
	return v, nil
}

func (v *passView) updateMove(msg tea.KeyMsg) (view, tea.Cmd) {
	switch msg.String() {
	case "esc":
		v.mode = smList
		return v, nil
	case "enter":
		e, ok := v.current()
		if !ok {
			v.mode = smList
			return v, failure("no entry selected")
		}
		to := strings.Trim(strings.TrimSpace(v.move.String()), "/")
		v.mode = smList
		if err := passstore.Move(e.Name, to); err != nil {
			return v, failure("%v", err)
		}
		return v, tea.Batch(status("%s → %s", e.Name, to), reload)
	}
	v.move.update(msg)
	return v, nil
}

func (v *passView) updateFilter(msg tea.KeyMsg) (view, tea.Cmd) {
	switch msg.String() {
	case "esc":
		v.filter.set("")
		v.applyFilter()
		v.mode = smList
		return v, nil
	case "enter":
		v.mode = smList
		return v, nil
	}
	v.filter.update(msg)
	v.applyFilter()
	return v, nil
}

func (v *passView) updateConfirm(msg tea.KeyMsg) (view, tea.Cmd) {
	e, ok := v.current()
	if !ok {
		v.mode = smList
		return v, nil
	}
	switch msg.String() {
	case "y", "Y":
		v.mode = smList
		if err := passstore.Remove(e.Name); err != nil {
			return v, failure("%v", err)
		}
		return v, tea.Batch(status("deleted: %s", e.Name), reload)
	default:
		v.mode = smList
		return v, nil
	}
}

// renderDetail shows what is known about an entry without showing the entry.
//
// The password is decrypted to read any of this — the whole file comes out at once — but it is
// dropped in passstore.Fields and never arrives here, so there is no version of this screen that
// can leak it by accident.
func (v *passView) renderDetail(w int) string {
	e := v.detailEntry
	// Every value is cut to the box, because a store path is easily longer than the terminal and a
	// wrapped line walks straight through the right border.
	room := maxi(w-20, 24)
	var b strings.Builder
	row := func(label, val string) {
		if val != "" {
			fmt.Fprintf(&b, "  %s %s\n", stDim.Render(fmt.Sprintf("%-12s", label)), val)
		}
	}
	row("path", stFg.Render(trunc(e.Name, room)))
	row("folder", trunc(e.Folder, room))
	row("file", stDim.Render(trunc(passstore.Dir()+"/"+e.Name+".gpg", room)))
	row("modified", e.Modified.Format("2006-01-02 15:04")+
		stDim.Render(fmt.Sprintf("  (%d days ago)", int(time.Since(e.Modified).Hours()/24))))

	switch {
	case v.detailErr != "":
		b.WriteString("\n" + stWarn.Render("  the fields cannot be read: "+trunc(v.detailErr, room)) + "\n")
		b.WriteString(stDim.Render("  usually means the gpg agent is locked — copy once with [c]") + "\n")
	case len(v.detailFields) == 0:
		b.WriteString("\n" + stDim.Render("  the entry has no fields beyond the password itself") + "\n")
	default:
		b.WriteString("\n")
		for _, k := range sortedKeys(v.detailFields) {
			row(k, stFg.Render(trunc(v.detailFields[k], room)))
		}
		b.WriteString("\n" + stDim.Render("  The password is not shown here. [c] hands it straight to the clipboard\n"+
			"  without passing through keyforge, and pass clears it after 45 seconds."))
	}
	return stBox.Width(w - 2).Render(b.String())
}

func (v *passView) Render(w, h int) string {
	switch v.mode {
	case smForm:
		return v.form.render(w)
	case smMove:
		return v.renderMove(w)
	case smConfirm:
		return v.renderConfirm(w)
	case smDetail:
		return v.renderDetail(w)
	}
	return v.renderList(w, h)
}

// renderMaster is the one line that says whether any of this is protected at all.
func (v *passView) renderMaster() string {
	rec := passstore.Recipient()
	if len(rec) > 16 {
		rec = rec[len(rec)-16:]
	}
	var state string
	switch {
	case !v.prot.Known:
		state = stDim.Render("passphrase: not verified")
	case !v.prot.Protected:
		state = stBad.Render("NO PASSPHRASE — a copy of the store opens immediately")
	case v.prot.Cached:
		state = stWarn.Render("unlocked in the agent") +
			stDim.Render(fmt.Sprintf(" · up to %s with no prompt", short(v.ttl.Default)))
	default:
		state = stGood.Render("locked")
	}
	return fmt.Sprintf("  %s %s   %s\n", stDim.Render("store →"), stFg.Render(rec), state)
}

func (v *passView) renderList(w, h int) string {
	if !v.loaded {
		return stDim.Render("  reading the store…")
	}
	if v.err != "" {
		return stErr.Render("  " + v.err)
	}

	var b strings.Builder
	b.WriteString(v.renderMaster())

	if v.mode == smFilter || strings.TrimSpace(v.filter.String()) != "" {
		b.WriteString("  " + v.filter.render(v.mode == smFilter) + "\n")
	}
	b.WriteString("\n")

	if len(v.entries) == 0 {
		b.WriteString(stDim.Render("  the store is empty — press [a] for the first entry"))
		return b.String()
	}
	if len(v.shown) == 0 {
		b.WriteString(stDim.Render("  nothing matches the filter"))
		return b.String()
	}

	// Folders are headers rather than rows: they are not things you can copy or delete, and making
	// them selectable would mean every other keypress landing on something that cannot do anything.
	lastFolder := "\x00"
	for i, e := range v.shown {
		if e.Folder != lastFolder {
			lastFolder = e.Folder
			label := e.Folder
			if label == "" {
				label = "(at the root)"
			}
			b.WriteString("  " + stAccent.Render(label+"/") + "\n")
		}
		mark := "  "
		row := stRow
		if i == v.sel {
			mark = stKey.Render(pointer) + " "
			row = stRowSel
		}
		age := stDim.Background(row.GetBackground())
		line := cell("    "+e.Leaf, maxi(w-26, 20), row) + " " +
			cell(e.Modified.Format("2006-01-02"), 12, age)
		b.WriteString(mark + line + "\n")
	}

	b.WriteString("\n" + stDim.Render(fmt.Sprintf("  %d %s in %s", len(v.entries), plural(len(v.entries), "entry", "entries"), passstore.Dir())))
	return b.String()
}

func (v *passView) renderMove(w int) string {
	e, _ := v.current()
	var b strings.Builder
	b.WriteString(stAccent.Render("  Move / rename") + "\n\n")
	b.WriteString("  " + stDim.Render("from: ") + stFg.Render(e.Name) + "\n")
	b.WriteString("  " + v.move.render(true) + "\n\n")
	b.WriteString(stDim.Render("  The path is also the folder: `websites/retired/…` is how an account is\n" +
		"  put away without losing what its password was. The entry travels\n" +
		"  encrypted — pass does not open it in order to move it."))
	return stBox.Width(w - 2).Render(b.String())
}

func (v *passView) renderConfirm(w int) string {
	e, _ := v.current()
	var b strings.Builder
	b.WriteString(stBad.Render("  Delete entry") + "\n\n")
	b.WriteString("  " + stFg.Render(e.Name) + "\n\n")
	b.WriteString(stDim.Render("  If the store is a git repository, the entry stays in its history and can\n" +
		"  be recovered from there. If it is not, this is final."))
	b.WriteString("\n\n  " + stWarn.Render("[y] delete") + stDim.Render("   any other key cancels"))
	return stBox.Width(w - 2).Render(b.String())
}

func (v *passView) Footer() string {
	switch v.mode {
	case smForm:
		return v.form.footer()
	case smMove:
		return joinHints(hint("enter", "move"), hint("esc", "cancel"))
	case smFilter:
		return joinHints(hint("enter", "apply"), hint("esc", "clear"))
	case smConfirm:
		return joinHints(hint("y", "delete"), hint("other", "cancel"))
	case smDetail:
		return joinHints(hint("esc", "back"))
	}
	return joinHints(
		hint("a", "new"), hint("e", "change"), hint("c", "copy"),
		hint("m", "move"), hint("d", "delete"), hint("/", "filter"),
		hint("enter", "details"), hint("p", "master password"),
	)
}

// short renders a cache lifetime the way a person would say it.
func short(d time.Duration) string {
	switch {
	case d <= 0:
		return "?"
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	default:
		return fmt.Sprintf("%dh", int(d.Hours()))
	}
}
