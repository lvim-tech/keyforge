package ui

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/lvim-tech/keyforge/internal/passgen"
	"github.com/lvim-tech/keyforge/internal/passstore"
	"github.com/lvim-tech/keyforge/internal/sheet"
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

	// What the entry looked like when the form opened, so submit can tell what actually
	// changed. Without it every save would rewrite the file, and rewriting is the expensive
	// half — it needs the passphrase, while a rename does not.
	origLogin string
	origURL   string

	// origBody is the entry's metadata block exactly as it was stored, and it is carried through
	// the form for one reason: an edit must not lose what the form has no field for. The form
	// shows login and url; a real entry may also hold a note keyforge's own Print tab wrote, an
	// otp: line, or a block of recovery codes with no colon in them at all. Rebuilding the entry
	// from the two visible fields deleted every one of those on a routine password change.
	origBody string

	folders []string

	// The rule, read on demand: ctrl+g must respect it for the same reason the Generator does
	// — a password this form creates is one the paper may later have to carry.
	rules *ruleCache
	// po is the phrase shape this form generates with: the config's word count and separator,
	// or the Generator's live settings when the form was opened from there. Held rather than
	// rebuilt from passgen's defaults, which is what made ctrl+g ignore the config entirely.
	po passgen.PhraseOptions
}

// newPassForm builds an empty form for a new entry. folder pre-fills the path, so adding a second
// login under websites/abv.bg does not mean typing the whole path again.
func newPassForm(folder string) *passForm {
	f := &passForm{
		title:   "New entry in pass",
		path:    newInput("path", "websites/example.com/user@example.com"),
		sec:     newSecretInput("password", "type one, or ctrl+g for a new one"),
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
// fields are whatever metadata could be read back and body is that same metadata verbatim; when the
// agent was locked and nothing could be read, the form says so rather than silently writing the
// entry back with its login and url missing.
func newPassFormReplace(name string, fields map[string]string, body, readErr string) *passForm {
	f := newPassForm("")
	f.title = "Edit " + name
	f.replace, f.fixed = true, name
	f.field = 1 // start on the password; the path is above it and rarely the thing being changed
	f.path.set(name)
	f.login.set(fields["login"])
	f.url.set(fields["url"])
	f.origLogin, f.origURL = fields["login"], fields["url"]
	f.origBody = body
	if readErr != "" {
		f.metaErr = readErr
	}
	return f
}

// fieldOrder is the tab ring, which is not fixed: the path disappears when replacing and the
// confirmation appears only for a typed value.
func (f *passForm) fieldOrder() []int {
	// 0 path · 1 secret · 2 confirm · 3 login · 4 url
	// The path is editable in an edit too: renaming is the one change `pass` can make
	// without opening the file, and a form that would not let you do it sent you to a
	// different command for the cheapest operation there is.
	out := []int{0, 1}
	if f.needsConfirm() {
		out = append(out, 2)
	}
	return append(out, 3, 4)
}

// keepsExisting reports an edit that is leaving the password alone.
//
// The password field starts empty in an edit, because there is nothing sensible to pre-fill
// a masked field with. So empty means "the one already there", and the login and url mean
// the opposite — they ARE pre-filled, so whatever is left in them is what gets written.
// Stated on the form rather than left to be discovered.
func (f *passForm) keepsExisting() bool { return f.replace && f.sec.empty() }

// needsConfirm reports whether the value has to be typed twice. A generated one does not: it was
// never typed, so there is nothing to have mistyped, and `pass insert` skips its own second prompt
// on the same reasoning when it is fed a value.
func (f *passForm) needsConfirm() bool { return f.bits == 0 && !f.keepsExisting() }

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
		// The SAME generation as the Generator tab, for the same two reasons it exists there:
		// the configured shape (words, separator), and the rule COMPOSED IN rather than merely
		// avoided. This used to call passgen defaults with only the reserved characters set,
		// so a password born in this form ignored the config and carried no marker value —
		// and a password with no value in it prints as a sheet that is enough on its own.
		o := f.po
		if o.Words <= 0 {
			o = passgen.DefaultPhraseOptions()
		}
		var m sheet.Mask
		if f.rules != nil {
			r, rerr := f.rules.get()
			if rerr != nil {
				// Refused rather than generated without the rule: see genView.regen.
				return failure("%v", rerr)
			}
			m = r.Mask()
			o.Reserved = m.Reserved()
		}
		base, bits, err := passgen.Phrase(o)
		if err != nil {
			return failure("generator: %v", err)
		}
		_, v := sheet.Compose(base, m)
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
	name := strings.Trim(strings.TrimSpace(f.path.String()), "/")
	if err := passstore.ValidName(name); err != nil {
		return "", err
	}
	if f.sec.empty() && !f.replace {
		return "", fmt.Errorf("the password is empty")
	}
	if f.needsConfirm() && !f.sec.secret().Equal(f.confirm.secret()) {
		return "", fmt.Errorf("the two entries do not match")
	}

	// A typed value that ran out of buffer is refused rather than stored. The confirmation field
	// truncates at exactly the same byte, so the two halves of a 600-character paste "match" and
	// the store quietly keeps the first 512 — a password that will never open anything.
	if f.sec.overflowed() || f.confirm.overflowed() {
		return "", fmt.Errorf("the password is longer than this field can hold — it would be stored cut short")
	}

	login := strings.TrimSpace(f.login.String())
	url := strings.TrimSpace(f.url.String())
	meta := map[string]string{}
	if login != "" {
		meta["login"] = login
	}
	if url != "" {
		meta["url"] = url
	}
	if f.bits > 0 {
		meta["generated-by"] = "keyforge"
		meta["entropy"] = fmt.Sprintf("%.0f bits", f.bits)
	}

	if !f.replace {
		return name, passstore.InsertSecret(name, f.sec.secret(), meta)
	}

	// An edit is up to three different operations, and telling them apart is the whole
	// point of this branch. Renaming moves the ciphertext and never opens it. Rewriting the
	// contents needs the password in hand, which — when it is being kept rather than
	// replaced — means reading it back first. Doing the second when only the first was asked
	// for would demand a passphrase for changing a folder name.
	renamed := name != f.fixed
	if renamed {
		if err := passstore.Move(f.fixed, name); err != nil {
			return "", err
		}
	}

	contentsChanged := !f.sec.empty() || login != f.origLogin || url != f.origURL
	if !contentsChanged {
		if renamed {
			return name, nil
		}
		return name, fmt.Errorf("nothing was changed")
	}

	// The metadata is EDITED rather than rebuilt: the block that was there comes back with only
	// login and url changed, so a note, an otp: line or a block of recovery codes survives a
	// password change instead of being deleted by an entry form that has no field for it.
	body := passstore.SetFields(f.origBody, f.metaChanges(login, url))

	if f.sec.empty() {
		cur, rerr := passstore.Reveal(name)
		if rerr != nil {
			return "", fmt.Errorf("the password could not be read back, so it cannot be kept: %v", rerr)
		}
		err := passstore.ReplaceBody(name, cur, body)
		cur.Close()
		return name, err
	}
	return name, passstore.ReplaceBody(name, f.sec.secret(), body)
}

// metaChanges is the set of fields an edit actually asserts something about.
//
// Only these are touched in the stored block; a value of "" removes the line, which is how a login
// that has been cleared in the form disappears from the entry. generated-by/entropy join the set
// only when the value being written was generated here — leaving the old entry's figures alone
// would claim an entropy for a password that no longer has it.
func (f *passForm) metaChanges(login, url string) map[string]string {
	set := map[string]string{"login": login, "url": url}
	if f.bits > 0 {
		set["generated-by"] = "keyforge"
		set["entropy"] = fmt.Sprintf("%.0f bits", f.bits)
	}
	return set
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

	b.WriteString("  " + f.path.render(f.focused(0)) + "\n")
	if f.replace {
		b.WriteString(stDim.Render("           changing it renames the entry — no passphrase needed for that") + "\n")
	}
	b.WriteString("  " + f.sec.render(f.focused(1)) + "\n")
	if f.replace && f.sec.empty() {
		b.WriteString(stDim.Render("           leave it blank to keep the password that is there") + "\n")
	}
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
