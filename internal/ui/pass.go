package ui

import (
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/lvim-tech/keyforge/internal/config"
	"github.com/lvim-tech/keyforge/internal/gpgkeys"
	"github.com/lvim-tech/keyforge/internal/passgen"
	"github.com/lvim-tech/keyforge/internal/passstore"
	"github.com/lvim-tech/keyforge/internal/sys"
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
	// po is the configured phrase shape, handed to any form this view opens.
	po passgen.PhraseOptions

	entries []passstore.Entry
	shown   []passstore.Entry // entries after the filter — what the tree is built from

	// The tree, and the rows it currently draws.
	//
	// A store is a directory of directories and it was being shown as one flat alphabetical list
	// with the folders printed above their contents as headers you could not stand on. That reads
	// well for twenty entries and not at all for two hundred: there is no way to put a branch away,
	// and no way to say that one folder matters more than the one whose name happens to start with
	// an earlier letter. Both are what a tree is for.
	root *treeNode
	rows []*treeNode // one per drawn line, folders included

	// open is which folders are unfolded, by store path. It outlives the process in keyforge's
	// config directory — see config.TreeState for why it is kept there and the ORDER is not.
	open map[string]bool

	sel    int
	loaded bool
	err    string

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

	// A revealed password lives here and only here: in locked memory, for one entry, until the
	// shared timer fires or the pane is left. Never turned on by itself.
	rev      reveal
	revealed *sys.Secret

	// Handed to every form this tab opens, so a password created here honours the rule.
	rules *ruleCache
}

func newPassView(c config.Config, rules *ruleCache) *passView {
	// The phrase shape from the config, so ctrl+g in this tab's form produces the same kind of
	// passphrase as everywhere else rather than passgen's bare defaults.
	po := passgen.DefaultPhraseOptions()
	if c.PhraseWords > 0 {
		po.Words = c.PhraseWords
	}
	if c.Separator != "" {
		po.Separator = c.Separator
	}
	v := &passView{
		rules:  rules,
		po:     po,
		move:   newInput("new path", "websites/example.com/user"),
		filter: newInput("filter", "part of the path"),
		// Which folders were open the last time is read here rather than defaulted, so opening
		// keyforge lands you where you left it. A machine with no state file starts with the
		// root level showing and everything under it folded.
		open: openSet(config.LoadTreeState()),
	}
	// The shared reveal owns the timer and the toggle; wiping the locked buffer is this view's
	// part of it, because it is the only one holding one.
	v.rev.onHide = func() {
		if v.revealed != nil {
			v.revealed.Close()
			v.revealed = nil
		}
	}
	return v
}

func (v *passView) Title() string { return "Passwords" }

// capturesInput reports that the shell must not read the keys itself.
//
// Every mode but the list, not just the ones that take typing. The shell handles q, tab, h and l
// before the view sees them, so the detail pane's own "q means back" branch was unreachable and the
// key quit the whole program instead; worse, tab walked out of the delete confirmation while the
// view stayed in it, so coming back to the tab dropped the user into a confirmation raised minutes
// earlier. A modal pane owns the keyboard until it is left — that is what makes it modal.
func (v *passView) capturesInput() bool { return v.mode != smList }

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

// node is the row the cursor is on, folder or entry.
func (v *passView) node() *treeNode {
	if v.sel < 0 || v.sel >= len(v.rows) {
		return nil
	}
	return v.rows[v.sel]
}

// current is the selected ENTRY, and deliberately not the selected node.
//
// A folder is now a row like any other, so every key that acts on a record — copy, reveal, edit,
// move, delete — has to be able to answer "that is a folder". Returning the folder's own path as
// if it were an entry name is how [d] would come to delete a branch nobody asked about.
func (v *passView) current() (passstore.Entry, bool) {
	n := v.node()
	if n == nil || n.folder {
		return passstore.Entry{}, false
	}
	return n.entry, true
}

// needEntry is the soft failure the folder rows made necessary: it says WHICH of the two
// possible mistakes was made, because "no entry selected" on a row that plainly names something
// reads as a broken program.
func (v *passView) needEntry() (passstore.Entry, tea.Cmd) {
	n := v.node()
	switch {
	case n == nil:
		return passstore.Entry{}, failure("no entry selected")
	case n.folder:
		return passstore.Entry{}, failure("%s is a folder — select an entry inside it", n.leaf)
	}
	return n.entry, nil
}

// rebuild re-reads the shape of everything: the filter, the tree under it, and the drawn rows.
//
// It reads each folder's .order, so it belongs on the events that change what the tree IS —
// a reload, a filter, a reorder — and not on folding, which only changes what is shown.
func (v *passView) rebuild() {
	v.applyFilter()
	v.root = buildTree(v.shown)
	v.reflow()
}

// reflow recomputes the visible rows and keeps the cursor on the node it was already on.
//
// By PATH rather than by index: folding a branch above the cursor moves every row below it, and a
// cursor that stayed on row eleven would be pointing at a different password than the one the
// user was looking at. When the node is gone — filtered away, deleted — the old index is kept
// instead, which lands the cursor where the row used to be.
func (v *passView) reflow() {
	want, at := "", v.sel
	if n := v.node(); n != nil {
		want = n.path
	}
	v.rows = visibleRows(v.root, v.open, v.rows[:0])
	v.sel = max(0, mini(at, len(v.rows)-1))
	for i, n := range v.rows {
		if n.path == want {
			v.sel = i
			return
		}
	}
}

// applyFilter recomputes the entries the tree is built from, and unfolds the way to them.
func (v *passView) applyFilter() {
	q := strings.ToLower(strings.TrimSpace(v.filter.String()))
	if q == "" {
		v.shown = v.entries
		return
	}
	v.shown = nil
	for _, e := range v.entries {
		if !strings.Contains(strings.ToLower(e.Name), q) {
			continue
		}
		v.shown = append(v.shown, e)
		// A match inside a folded folder is a match nobody can see, and a filter that finds
		// nothing visible is indistinguishable from one that found nothing. The folders on the
		// way are opened in the STATE rather than around it, so [space] can still fold what the
		// search opened instead of fighting it.
		for _, f := range ancestors(e.Name) {
			v.open[f] = true
		}
	}
	// Not saved. What a search had to open is not where the user chose to be looking, and
	// writing the state file on every keystroke of a filter would make it so.
}

func (v *passView) Update(msg tea.Msg) (view, tea.Cmd) {
	// The hide timer arrives by broadcast rather than as a key press, so it is taken first.
	if v.rev.expired(msg) {
		return v, nil
	}
	if _, ok := msg.(forgetMsg); ok {
		// A password revealed on screen when the lock closes is a password on screen.
		v.rev.hide()
		v.detailFields, v.detailErr = nil, ""
		return v, nil
	}
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
		v.rebuild()
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
			case "v":
				return v.toggleReveal()
			case "c":
				// The pane's own text explains what [c] does — and the key did nothing here,
				// because only the list handled it. A screen that describes a key it does not
				// have is worse than one that stays silent: it is read as a broken program
				// rather than as a missing feature.
				//
				// Same path as the list: `pass` decrypts straight into the clipboard helper and
				// clears it again by itself, so the password never comes through keyforge.
				e := v.detailEntry
				if e.Name == "" {
					return v, failure("no entry selected")
				}
				return v, v.copyCmd(e)
			case "esc", "enter", "q":
				// Leaving the pane is one of the ways a password gets left on screen; it is also
				// the one the user is least likely to think about.
				v.rev.hide()
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
	// The cursor walks the VISIBLE rows, so a folded branch is skipped rather than walked through
	// invisibly — which is the whole point of being able to fold it.
	case "j", "down":
		if v.sel < len(v.rows)-1 {
			v.sel++
			v.rev.hide()
		}
	case "k", "up":
		if v.sel > 0 {
			v.sel--
			v.rev.hide()
		}
	case "g":
		v.sel = 0
		v.rev.hide()
	case "G":
		v.sel = max(0, len(v.rows)-1)
		v.rev.hide()

	// Folding is on [space], and reordering on the SHIFTED j and k — the mirror of the keys that
	// move the cursor, which is the only pair still free. The obvious ones are not: h, l, q, tab,
	// ctrl+c and ctrl+f are read by the shell before this view sees them, and so are both arrows,
	// because left and right change tabs.
	case " ":
		return v, v.toggleFold()
	case "K":
		return v, v.reorder(-1)
	case "J":
		return v, v.reorder(1)

	case "v":
		return v.toggleReveal()

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
		// Standing ON a folder now means exactly that: the entry starts inside it, which is the
		// one thing [a] can usefully do with a row that is not a record.
		folder := ""
		if n := v.node(); n != nil {
			folder = n.entry.Folder
			if n.folder {
				folder = n.path
			}
		}
		v.form = newPassForm(folder)
		v.form.rules, v.form.po = v.rules, v.po
		v.mode = smForm

	case "e":
		e, cmd := v.needEntry()
		if cmd != nil {
			return v, cmd
		}
		// Rewriting the entry replaces the whole file, metadata included, so the old fields are read
		// back first and carried over. That read decrypts, and decryption can fail with the agent
		// locked — in which case the form says so instead of quietly dropping login and url.
		fields, body, err := passstore.Body(e.Name)
		readErr := ""
		if err != nil {
			readErr = err.Error()
			fields, body = map[string]string{}, ""
		}
		v.form = newPassFormReplace(e.Name, fields, body, readErr)
		v.form.rules, v.form.po = v.rules, v.po
		v.mode = smForm

	case "c":
		e, cmd := v.needEntry()
		if cmd != nil {
			return v, cmd
		}
		// pass decrypts and hands the value straight to the clipboard helper, then clears it again
		// by itself, so this path never brings the password through keyforge at all. [v] does, and
		// that is the whole difference between them: this one is for using the password, that one
		// is for reading it.
		return v, v.copyCmd(e)

	case "enter", "f":
		// On a folder both keys mean the same thing they mean on an entry: open this. There is
		// nothing to show about a folder that its own row does not already say.
		if n := v.node(); n != nil && n.folder {
			return v, v.toggleFold()
		}
		e, cmd := v.needEntry()
		if cmd != nil {
			return v, cmd
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
		e, cmd := v.needEntry()
		if cmd != nil {
			return v, cmd
		}
		v.move.set(e.Name)
		v.mode = smMove

	case "d":
		if _, cmd := v.needEntry(); cmd != nil {
			return v, cmd
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

// toggleFold opens or folds the selected folder, and remembers which it was.
//
// The state is written NOW rather than on the way out. keyforge is a program people leave open
// for days and eventually kill from another terminal, and a fold state that only survives a
// clean quit is one that mostly does not survive.
func (v *passView) toggleFold() tea.Cmd {
	n := v.node()
	if n == nil || !n.folder {
		return nil
	}
	if v.open[n.path] {
		delete(v.open, n.path)
	} else {
		v.open[n.path] = true
	}
	v.reflow()
	if err := config.SaveTreeState(treeState(v.open, folderPaths(v.entries))); err != nil {
		// Said out loud rather than swallowed: the tree still folds, but it will forget by the
		// next run, and a program that quietly stops remembering is one you stop trusting to.
		return failure("the tree state could not be saved: %v", err)
	}
	return nil
}

// reorder moves the selected node one place among its siblings and records the new order.
//
// The order goes into a .order file in that folder, INSIDE the store, because it is part of how
// the store is organised: it belongs in the git repository the store usually is, and on every
// machine that syncs it. Which folders are open is the opposite kind of fact and is kept out of
// the store entirely — see config.TreeState.
func (v *passView) reorder(d int) tea.Cmd {
	n := v.node()
	if n == nil {
		return failure("nothing is selected")
	}
	// Refused under a filter, and this is not caution but correctness: the tree then holds only
	// the matching children, and writing THAT as the folder's order would pin the matches to the
	// top of a folder whose other entries were never on screen to be moved.
	if strings.TrimSpace(v.filter.String()) != "" {
		return failure("clear the filter first — the order is the whole folder's, not the matches'")
	}
	if !shift(n, d) {
		where := "first"
		if d > 0 {
			where = "last"
		}
		return failure("%s is already %s in %s", n.leaf, where, parentName(n))
	}
	p := n.parent
	if err := passstore.SetOrder(p.path, siblingKeys(p)); err != nil {
		// Put back. A screen showing an order the store does not have is a screen that will
		// rearrange itself on the next reload with no explanation.
		shift(n, -d)
		return failure("%v", err)
	}
	v.reflow()
	return status("%s moved in %s", n.leaf, parentName(n))
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
		v.rebuild()
		v.mode = smList
		return v, nil
	case "enter":
		v.mode = smList
		return v, nil
	}
	v.filter.update(msg)
	v.rebuild()
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

// toggleReveal decrypts the selected entry and puts its password on screen, or takes it away again.
//
// The value never becomes a Go string on the way here: `pass show` writes into a pipe passstore
// opens itself and the bytes land in locked memory. It becomes one only for the instant it is drawn,
// which is unavoidable — a terminal takes strings.
// copyCmd copies an entry, taking over the terminal ONLY when something might need it.
//
// Every copy used to go through tea.ExecProcess, which suspends the interface, hands the real
// terminal to `pass`, waits, and takes it back. That is necessary exactly once — when the agent
// has forgotten the passphrase and pinentry has to draw its prompt somewhere — and for every
// other copy it is a visible flash of the shell underneath, on the most-used key in the tab.
//
// So the quiet path is tried first whenever the agent is holding the passphrase, and a failure
// falls back to the interactive one rather than guessing why. The cache can expire between the
// read that filled v.prot and this keypress; asking again with the terminal in hand is both the
// correct answer to that and the only case the suspend was ever for.
//
// NOTHING IS PIPED. `pass show --clip` forks a sleeper that clears the clipboard 45 seconds
// later, and that child inherits whatever stdout and stderr it is given. A pipe — which is what
// a strings.Builder becomes here — would stay open in the sleeper, so cmd.Run would block for
// the whole 45 seconds waiting for an EOF that had not come yet. /dev/null does not have that
// problem, at the price of the error TEXT; the exit code is enough to decide to retry.
func (v *passView) copyCmd(e passstore.Entry) tea.Cmd {
	done := fmt.Sprintf("%s is on the clipboard — pass will clear it by itself", e.Leaf)
	interactive := func() tea.Msg {
		return execMsg{cmd: passstore.CopyCmd(e.Name), then: done}
	}
	// A prompt is possible only when the key HAS a passphrase and the agent is not holding it.
	// Testing `Cached` alone got the unprotected store wrong: there is nothing to ask for there,
	// yet every copy still suspended the interface to make room for a prompt that cannot happen.
	// `Known` is false when the agent did not answer at all — then assume the worst and hand
	// over the terminal, because a guess that costs a flash is better than one that loses a
	// prompt.
	if !v.prot.Known || (v.prot.Protected && !v.prot.Cached) {
		return interactive
	}
	return func() tea.Msg {
		cmd := passstore.CopyCmd(e.Name)
		cmd.Stdin, cmd.Stdout, cmd.Stderr = nil, nil, nil
		if err := cmd.Run(); err != nil {
			return interactive()
		}
		return statusMsg{text: done}
	}
}

func (v *passView) toggleReveal() (view, tea.Cmd) {
	if v.rev.on {
		v.rev.hide()
		return v, nil
	}
	e, cmd := v.needEntry()
	if cmd != nil {
		return v, cmd
	}
	sec, err := passstore.Reveal(e.Name)
	if err != nil {
		return v, failure("%v", err)
	}
	v.revealed = sec
	return v, tea.Batch(
		v.rev.show(),
		status("%s is on screen for %s — [v] hides it now", e.Leaf, short(revealTimeout)),
	)
}

// revealedLine renders the password when it is showing, and says so when it is not.
func (v *passView) revealedLine(room int) string {
	if !v.rev.on || v.revealed == nil {
		return stDim.Render("  password     ") + stDim.Render("•••••••• ") + stKey.Render("[v]") + stDim.Render(" shows it")
	}
	// Folded, not cut — and folded by RUNES, not by words. A password shown as "hunter2-corr…"
	// is a password you cannot read, and one run through wrapText is a password you can read
	// wrong: that function normalises whitespace, so a value holding two spaces was displayed
	// with one. Reading the exact value is the entire reason [v] exists.
	shown := ""
	v.revealed.Use(func(s string) { shown = foldRunes(s, room) })
	out := ""
	for i, l := range strings.Split(shown, "\n") {
		if i == 0 {
			out = stDim.Render("  password     ") + stFg.Render(l)
			continue
		}
		out += "\n" + strings.Repeat(" ", 15) + stFg.Render(l)
	}
	return out + stWarn.Render("   on screen — [v] hides it")
}

// renderDetail shows what is known about an entry without showing the entry.
//
// The password is decrypted to read any of this — the whole file comes out at once — but it is
// dropped in passstore.Fields and never arrives here, so there is no version of this screen that
// can leak it by accident.
func (v *passView) renderDetail(w int) string {
	e := v.detailEntry
	// Values are FOLDED, not cut. The old reasoning was that a store path is easily longer than
	// the terminal and a wrapped line walks through the right border — true of a line that
	// wraps by accident, at the terminal's width, and not of one folded to the box's own width
	// with its continuation aligned under the column. Cutting made the box tidy and the answer
	// unreadable: a path ending in "…" does not say which entry you are looking at, which is
	// the only question this pane exists to answer.
	room := max(w-20, 24)
	var b strings.Builder
	row := func(label, val string, st lipgloss.Style) {
		if val == "" {
			return
		}
		for i, l := range strings.Split(wrapText(val, room), "\n") {
			if i == 0 {
				fmt.Fprintf(&b, "  %s %s\n", stDim.Render(fmt.Sprintf("%-12s", label)), st.Render(l))
				continue
			}
			// Plain spaces, not a styled blank: the padding carries no meaning and a
			// whitespace-only Render is the sort of thing a layout engine feels free to trim.
			fmt.Fprintf(&b, "%s%s\n", strings.Repeat(" ", 15), st.Render(l))
		}
	}
	row("path", e.Name, stFg)
	row("folder", e.Folder, stDim)
	row("file", passstore.Dir()+"/"+e.Name+".gpg", stDim)
	fmt.Fprintf(&b, "  %s %s%s\n", stDim.Render(fmt.Sprintf("%-12s", "modified")),
		e.Modified.Format("2006-01-02 15:04"),
		stDim.Render(fmt.Sprintf("  (%d days ago)", int(time.Since(e.Modified).Hours()/24))))

	b.WriteString(v.revealedLine(room) + "\n")

	switch {
	case v.detailErr != "":
		b.WriteString("\n" + indent(stWarn.Render(wrapText("the fields cannot be read: "+v.detailErr, room)), 2) + "\n")
		b.WriteString(stDim.Render("  usually means the gpg agent is locked — copy once with [c]") + "\n")
	case len(v.detailFields) == 0:
		b.WriteString("\n" + stDim.Render("  the entry has no fields beyond the password itself") + "\n")
	default:
		b.WriteString("\n")
		for _, k := range sortedKeys(v.detailFields) {
			row(k, v.detailFields[k], stFg)
		}
		b.WriteString("\n" + stDim.Render("  [c] hands the password straight to the clipboard without it passing\n"+
			"  through keyforge at all, and pass clears it after 45 seconds. [v] brings\n"+
			"  it here instead — read it, and it goes away by itself."))
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
	head := v.renderMaster()
	if v.mode == smFilter || strings.TrimSpace(v.filter.String()) != "" {
		head += "  " + v.filter.render(v.mode == smFilter) + "\n"
	}
	head += "\n"
	b.WriteString(head)

	if len(v.entries) == 0 {
		b.WriteString(stDim.Render("  the store is empty — press [a] for the first entry"))
		return b.String()
	}
	if len(v.rows) == 0 {
		b.WriteString(stDim.Render("  nothing matches the filter"))
		return b.String()
	}

	// Everything drawn UNDER the list, built before the list is windowed: the budget is
	// measured from what this frame really draws, not reserved for the worst case. The
	// reserve was three lines nothing used on an ordinary draw — and once the body is padded
	// to its height, three unused lines are three blank rows sitting under "… N below".
	under := ""
	if v.rev.on && v.revealed != nil {
		// [v] works from the list too, and until now it decrypted the entry, announced "on
		// screen for 30s", and drew nothing: revealedLine was called only by the detail pane.
		// A password held in locked memory for half a minute, announced, and never shown is
		// the worst trade of the three — all of the exposure and none of the use.
		under += "\n" + v.revealedLine(max(w-20, 24)) + "\n"
	}
	under += "\n" + stDim.Render(fmt.Sprintf("  %d %s in %s", len(v.entries), plural(len(v.entries), "entry", "entries"), passstore.Dir()))

	// ONE ROW PER VISIBLE NODE, folders included — which is what let the old walk go. It
	// measured the rendered height of a range of entries because a folder used to be a header
	// printed above the entries it held: a line belonging to no entry, which the shell then
	// cut off the bottom of a body that had drawn more lines than it was given. A folder is a
	// row you can stand on now, so height and count are the same number again.
	start, end := markedWindow(len(v.rows), v.sel, listBudget(h, head, under))
	if start > 0 {
		b.WriteString(stDim.Render(fmt.Sprintf("     … %d above", start)) + "\n")
	}
	for i, n := range v.rows[start:end] {
		i += start
		mark := "  "
		row := stRow
		if i == v.sel {
			mark = stKey.Render(pointer) + " "
			row = stRowSel
		}
		// The indent is the tree. Two columns a level, and a leaf carries the width of the marker
		// its folder would have, so the names of one folder's children line up under each other
		// instead of stepping sideways at every level.
		pad := strings.Repeat("  ", n.depth)
		right := stDim.Background(row.GetBackground())
		if n.folder {
			// ▸ folded, ▾ open — the state of the node, said on the node itself, because the only
			// other place it could be said is the absence of the rows underneath, and an empty
			// folder and a folded one would then look the same.
			glyph := "▸"
			if v.open[n.path] {
				glyph = "▾"
			}
			name := cell(pad+glyph+" "+n.leaf+"/", max(w-26, 20), stAccent.Background(row.GetBackground()))
			// How much it holds, which is the one thing worth knowing about a folder you have
			// just put away — a date would be the folder's, and nobody has ever wanted that.
			count := fmt.Sprintf("%d", n.records())
			b.WriteString(mark + name + " " + cell(count, 12, right) + "\n")
			continue
		}
		line := cell(pad+"  "+n.leaf, max(w-26, 20), row) + " " +
			cell(n.entry.Modified.Format("2006-01-02"), 12, right)
		b.WriteString(mark + line + "\n")
	}

	if end < len(v.rows) {
		b.WriteString(stDim.Render(fmt.Sprintf("     … %d below", len(v.rows)-end)) + "\n")
	}

	b.WriteString(under)
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
		return joinHints(hint("c", "copy"), revealHint(v.rev.on), hint("esc", "back"))
	}
	// Every key that acts is named. [r] re-read the store from the day this tab was written and
	// was never in the footer — the same drift the Generator's comment records for [x] and [a]:
	// the capability was on screen, the way to reach it was not.
	return joinHints(
		hint("j/k", "move"), hint("g/G", "top/bottom"),
		hint("space", "fold"), hint("K/J", "reorder"),
		hint("a", "new"), hint("e", "change"), hint("c", "copy"), revealHint(v.rev.on),
		hint("m", "move"), hint("d", "delete"), hint("/", "filter"), hint("r", "reload"),
		hint("enter/f", "open · details"), hint("p", "master password"),
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
