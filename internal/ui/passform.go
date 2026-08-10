package ui

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/lvim-tech/keyforge/internal/passgen"
	"github.com/lvim-tech/keyforge/internal/passstore"
)

// passForm is the one form that writes a secret into `pass`, shared by the generator — where the
// value arrives already made — and by the password list, where it is typed in.
//
// One type rather than two, and the reason is not tidiness. The rules that matter here (the path
// must be free, the value never becomes an argument, a typed value is confirmed before it is
// stored, the metadata follows the convention the rest of the pass ecosystem reads) must not be
// able to drift apart between the two doors a secret can walk through. A second copy of this form
// is a second place for one of those rules to quietly go missing.
type passForm struct {
	title   string
	replace bool   // overwrite an existing entry instead of refusing to
	fixed   string // when replacing: the entry being rewritten; the path is not editable

	path    input
	sec     *secretInput
	confirm *secretInput
	login   input
	url     input

	field int
	// bits is the entropy of a generated value and 0 for a typed one. It doubles as the flag for
	// "this came from the generator": a generated value needs no confirmation field, because there
	// was no keyboard between it and the store to get it wrong.
	bits float64

	// metaErr explains why an existing entry's metadata could not be read back, when it could not.
	// Saying it out loud is the point: rewriting the password of an entry whose login and url were
	// unreadable would drop them, and a store that silently loses fields is worse than one that
	// refuses.
	metaErr string

	folders []string
}

// newPassForm builds an empty form for a new entry. folder pre-fills the path, so adding a second
// login under websites/abv.bg does not mean typing the whole path again.
func newPassForm(folder string) *passForm {
	f := &passForm{
		title:   "New entry in pass",
		path:    newInput("path", "websites/example.com/user@example.com"),
		sec:     newSecretInput("password", "type the existing one, or ctrl+g for a new one"),
		confirm: newSecretInput("repeat", "the same one again"),
		login:   newInput("login", "optional — what goes in the username field"),
		url:     newInput("url", "optional — https://…"),
		folders: passstore.Folders(),
	}
	if folder != "" {
		f.path.set(folder + "/")
	}
	return f
}

// newPassFormGenerated is the generator's door: the value is already made and already measured.
func newPassFormGenerated(value string, bits float64) *passForm {
	f := newPassForm("")
	f.title = "Store the generated password in pass"
	f.sec.set(value)
	f.bits = bits
	return f
}

// newPassFormReplace rewrites the password of an entry that already exists.
//
// fields are whatever metadata could be read back; when the agent was locked and nothing could be,
// the form says so rather than silently writing the entry back with its login and url missing.
func newPassFormReplace(name string, fields map[string]string, readErr string) *passForm {
	f := newPassForm("")
	f.title = "Change the password of " + name
	f.replace, f.fixed = true, name
	f.field = 1 // the path is not in the ring when replacing; start on the password
	f.login.set(fields["login"])
	f.url.set(fields["url"])
	if readErr != "" {
		f.metaErr = readErr
	}
	return f
}

// fieldOrder is the tab ring, which is not fixed: the path disappears when replacing and the
// confirmation appears only for a typed value.
func (f *passForm) fieldOrder() []int {
	// 0 path · 1 secret · 2 confirm · 3 login · 4 url
	var out []int
	if !f.replace {
		out = append(out, 0)
	}
	out = append(out, 1)
	if f.needsConfirm() {
		out = append(out, 2)
	}
	return append(out, 3, 4)
}

// needsConfirm reports whether the value has to be typed twice. A generated one does not: it was
// never typed, so there is nothing to have mistyped, and `pass insert` skips its own second prompt
// on the same reasoning when it is fed a value.
func (f *passForm) needsConfirm() bool { return f.bits == 0 }

func (f *passForm) next(d int) {
	order := f.fieldOrder()
	at := 0
	for i, x := range order {
		if x == f.field {
			at = i
		}
	}
	f.field = order[(at+d+len(order))%len(order)]
}

// focused reports whether the given field index currently has the cursor.
func (f *passForm) focused(i int) bool { return f.field == i }

func (f *passForm) update(msg tea.KeyMsg) tea.Cmd {
	switch msg.String() {
	case "tab", "down":
		f.next(1)
		return nil
	case "shift+tab", "up":
		f.next(-1)
		return nil
	case "ctrl+g":
		v, bits, err := passgen.Phrase(passgen.DefaultPhraseOptions())
		if err != nil {
			return failure("generator: %v", err)
		}
		f.sec.set(v)
		f.confirm.reset()
		f.bits = bits
		if f.field == 2 {
			f.field = 1
		}
		label, _ := passgen.Strength(bits)
		return status("generated phrase · %.0f bits · %s", bits, label)
	}

	switch f.field {
	case 0:
		f.path.update(msg)
	case 1:
		if f.sec.update(msg) {
			// Touching the value by hand makes it a typed one again: it now needs confirming, and
			// the entropy of the phrase it replaced is no longer a fact about what will be stored.
			f.bits = 0
		}
	case 2:
		f.confirm.update(msg)
	case 3:
		f.login.update(msg)
	case 4:
		f.url.update(msg)
	}
	return nil
}

// submit writes the entry and returns the name it was stored under.
func (f *passForm) submit() (string, error) {
	name := f.fixed
	if !f.replace {
		name = strings.Trim(strings.TrimSpace(f.path.String()), "/")
		if err := passstore.ValidName(name); err != nil {
			return "", err
		}
	}
	if f.sec.empty() {
		return "", fmt.Errorf("the password is empty")
	}
	if f.needsConfirm() && !f.sec.secret().Equal(f.confirm.secret()) {
		return "", fmt.Errorf("the two entries do not match")
	}

	meta := map[string]string{}
	if v := strings.TrimSpace(f.login.String()); v != "" {
		meta["login"] = v
	}
	if v := strings.TrimSpace(f.url.String()); v != "" {
		meta["url"] = v
	}
	if f.bits > 0 {
		meta["generated-by"] = "keyforge"
		meta["entropy"] = fmt.Sprintf("%.0f bits", f.bits)
	}

	var err error
	if f.replace {
		err = passstore.Replace(name, f.sec.secret(), meta)
	} else {
		err = passstore.InsertSecret(name, f.sec.secret(), meta)
	}
	if err != nil {
		return "", err
	}
	return name, nil
}

// close releases the locked buffers. Every path out of the form goes through it — a form abandoned
// with esc leaves a passphrase pinned in memory otherwise.
func (f *passForm) close() {
	f.sec.close()
	f.confirm.close()
}

func (f *passForm) render(w int) string {
	var b strings.Builder
	b.WriteString(stAccent.Render("  "+f.title) + "\n\n")

	if f.replace {
		b.WriteString("  " + stDim.Render("path: ") + stFg.Render(f.fixed) + "\n")
	} else {
		b.WriteString("  " + f.path.render(f.focused(0)) + "\n")
	}
	b.WriteString("  " + f.sec.render(f.focused(1)) + "\n")
	if f.needsConfirm() {
		b.WriteString("  " + f.confirm.render(f.focused(2)) + "\n")
	} else if f.bits > 0 {
		label, detail := passgen.Strength(f.bits)
		st := stGood
		switch label {
		case "weak":
			st = stBad
		case "acceptable":
			st = stWarn
		}
		// detail already opens with the bit count; repeating it here printed "69 bits · 69 bits".
		b.WriteString("  " + stDim.Render("strength: ") + st.Render(label) +
			stDim.Render("  ·  "+detail) + "\n")
	}
	b.WriteString("  " + f.login.render(f.focused(3)) + "\n")
	b.WriteString("  " + f.url.render(f.focused(4)) + "\n\n")

	if f.metaErr != "" {
		b.WriteString(stWarn.Render("   the old fields could not be read: "+f.metaErr) + "\n")
		b.WriteString(stDim.Render("  the entry will keep only what is in the fields above") + "\n\n")
	}

	if !f.replace && len(f.folders) > 0 {
		b.WriteString(stDim.Render("  folders in the store: ") + stFg.Render(strings.Join(f.folders, "  ")) + "\n\n")
	}

	b.WriteString(stDim.Render("  The password reaches pass through a pipe keyforge builds itself —\n" +
		"  from locked memory straight into gpg, never across a command line\n" +
		"  and never as a string that cannot be erased afterwards.\n" +
		"  Encrypted to " + passstore.Recipient()))
	return stBox.Width(w - 2).Render(b.String())
}

func (f *passForm) footer() string {
	return joinHints(
		hint("enter", "store"), hint("tab", "field"),
		hint("ctrl+g", "generate"), hint("ctrl+u", "clear"), hint("esc", "cancel"),
	)
}
