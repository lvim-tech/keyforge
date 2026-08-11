package ui

import (
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/lvim-tech/keyforge/internal/config"
	"github.com/lvim-tech/keyforge/internal/passgen"
	"github.com/lvim-tech/keyforge/internal/passstore"
	"github.com/lvim-tech/keyforge/internal/sheet"
	"github.com/lvim-tech/keyforge/internal/sys"
)

type genView struct {
	phrase bool // word mode vs character mode

	po passgen.PhraseOptions
	co passgen.Options

	value string
	bits  float64
	err   string

	// form is the shared "write into pass" form, held open while a value is being stored. It is the
	// same one the Passwords tab uses, so a generated password and a typed one are written by identical
	// code — there is no second, slightly different path into the store.
	form *passForm

	// reserved characters the sheet rule has claimed as noise, and which therefore must never
	// appear in anything this program produces.
	//
	// The rule is a statement about every password keyforge makes, not about the ones that
	// happen to be made inside the printing tab. Generating without it here and printing with
	// it there is how a sheet ends up unable to carry a password keyforge itself created —
	// the reader deletes a character that was part of the password, and the paper backup
	// reconstructs something else.
	rules *ruleCache

	// offer is shown the first time a password is asked for on a machine with no rule.
	//
	// A rule cannot be applied backwards: passwords made before it exists can never go on a
	// masked sheet. So the one moment it is worth raising is the moment before the first
	// password — which is here, and nowhere else. It is an OFFER and not a demand: most
	// machines will never print anything, and a tool that refuses to work until a decision is
	// made teaches people to make it carelessly.
	offer bool
	// offered records that the question has been put once. Asked again on every [r] it would
	// be a demand wearing the clothes of an offer.
	offered bool
	// carriesRemembered is true when the value on screen has a marker's expansion inside it.
	carriesRemembered bool

	// rev masks the generated value until [v] is pressed. It used to print in the clear and stay
	// there: a phrase generated to be written down would sit on the screen for as long as the tab
	// was open, which is the one place a password is easiest to take and hardest to notice.
	rev reveal
}

// newGenView starts from the config, not from the package defaults.
//
// password_length, phrase_words and separator were written by the config and read by nobody
// here: the Generator built passgen.DefaultOptions() every time, so a config asking for 30
// characters produced 20 and nothing said why. Print already honoured the same field, which
// made the two tabs disagree about what "default" meant.
func newGenView(c config.Config, rules *ruleCache) *genView {
	po := passgen.DefaultPhraseOptions()
	co := passgen.DefaultOptions()
	if c.PasswordLength > 0 {
		co.Length = c.PasswordLength
	}
	if c.PhraseWords > 0 {
		po.Words = c.PhraseWords
	}
	if c.Separator != "" {
		po.Separator = c.Separator
	}
	if c.Ambiguous != "" {
		co.Ambiguous = c.Ambiguous
	}
	v := &genView{
		phrase: true,
		po:     po,
		co:     co,
		rules:  rules,
	}
	// Nothing is generated here. The first value would need the rule, and needing it at
	// construction is exactly what reading on demand was meant to stop: opening keyforge
	// would raise a prompt for the printing scheme before anything had been asked for.
	return v
}

// ambiguous is the set the "no ambiguous" switch removes, for the label that names it.
func (v *genView) ambiguous() string {
	if v.co.Ambiguous != "" {
		return v.co.Ambiguous
	}
	return passgen.DefaultAmbiguous()
}

func (v *genView) Title() string { return "Generator" }

func (v *genView) capturesInput() bool { return v.form != nil }

func (v *genView) Init() tea.Cmd { return nil }

func (v *genView) regen() {
	// A fresh value is a different secret; consent to seeing the last one does not carry over.
	v.rev.hide()

	// Two different situations, two different answers. No rule at all is the ordinary state
	// of a machine and gets the offer below. A rule that exists and cannot be read means
	// something is wrong, and generating anyway would produce a password that looks perfectly
	// good and can never go on a sheet — discovered on the day the sheet is the only copy
	// left.
	if !v.rules.configured() && !v.offered {
		v.offer = true
		v.value, v.bits, v.err = "", 0, ""
		return
	}
	r, err := v.rules.get()
	if err != nil {
		v.err = err.Error()
		v.value, v.bits = "", 0
		return
	}
	m := r.Mask()

	// THE RULE IS COMPOSED IN, not merely avoided. Until now this generator only refused to
	// emit the reserved characters, so a password made here carried no marker value at all —
	// and a marker can only go onto a sheet where the password actually contains what it
	// stands for. The result was a rule that worked for passwords made in Print and quietly
	// did nothing for the ones made here, which is where passwords are actually made.
	//
	// It matters beyond tidiness. The memorised half exists so that the PAPER IS NOT ENOUGH:
	// whoever holds the sheet still cannot reconstruct the password. A generated password
	// with no value in it puts the whole secret on the page, and the marker protects nothing.
	var base string
	if v.phrase {
		o := v.po
		o.Reserved = m.Reserved()
		base, v.bits, err = passgen.Phrase(o)
	} else {
		o := v.co
		o.Reserved = m.Reserved()
		// The PASSWORD is what this tab shows and stores, so the length the user set is the
		// length of that — not of the sheet line, which is Print's business.
		o.Length = v.co.Length - m.RealOverhead()
		if o.Length < 8 {
			o.Length = 8
		}
		base, v.bits, err = passgen.Password(o)
	}
	if err != nil {
		v.err = err.Error()
		v.value = ""
		return
	}
	v.err = ""
	_, v.value = sheet.Compose(base, m)
	v.carriesRemembered = len(m.Expand) > 0
}

// The clipboard clear is a package-level token rather than view state, for the same reason the
// reveal timer is: a second copy must cancel the first one's expiry, or the newer value is wiped
// early by the older timer.
var clipToken int

const clipTimeout = 45 * time.Second

type clipExpiredMsg int

func (v *genView) Update(msg tea.Msg) (view, tea.Cmd) {
	if t, ok := msg.(clipExpiredMsg); ok {
		if int(t) == clipToken {
			sys.ClearClipboard()
			return v, status("the clipboard was cleared")
		}
		return v, nil
	}
	// The hide timer is not a key press and arrives by broadcast, so it has to be taken before the
	// cast below throws away everything that is not one.
	if v.rev.expired(msg) {
		return v, nil
	}
	if _, ok := msg.(forgetMsg); ok {
		// The generated value is a secret this view is holding in the clear; the lock says the
		// store is shut, and a value still on the screen behind the curtain says otherwise.
		v.rev.hide()
		v.value, v.bits, v.err = "", 0, ""
		return v, nil
	}
	key, ok := msg.(tea.KeyMsg)
	if !ok {
		return v, nil
	}

	if v.form != nil {
		switch key.String() {
		case "esc":
			v.form.close()
			v.form = nil
			return v, nil
		case "enter":
			name, err := v.form.submit()
			if err != nil {
				return v, failure("%v", err)
			}
			v.form.close()
			v.form = nil
			// The Passwords tab is showing a list that just went out of date; reload tells it so.
			return v, tea.Batch(status("stored in pass as %s", name), reload)
		}
		if cmd := v.form.update(key); cmd != nil {
			return v, cmd
		}
		return v, nil
	}

	if v.offer {
		switch key.String() {
		case "y", "Y", "enter":
			v.offer, v.offered = false, true
			return v, func() tea.Msg { return openRuleMsg{} }
		default:
			// Declined, and not asked again this session. Passwords made from here on cannot
			// go on a masked sheet, which was said in the offer.
			v.offer, v.offered = false, true
			v.regen()
			return v, nil
		}
	}

	switch key.String() {
	case "v":
		return v, v.rev.toggle()
	case "r", " ":
		v.regen()
	case "m":
		v.phrase = !v.phrase
		v.regen()
	case "c":
		if v.value == "" {
			return v, failure("nothing to copy")
		}
		if err := sys.Clipboard(v.value); err != nil {
			return v, failure("clipboard: %v", err)
		}
		// Cleared on a timer, like the Passwords tab's `pass show --clip` — which the interface
		// already teaches the user to expect. This tab left brand-new passphrases sitting in
		// the most-taken-from place on the machine with no expiry at all.
		clipToken++
		token := clipToken
		return v, tea.Batch(
			status("copied — the clipboard is cleared in %s", short(clipTimeout)),
			tea.Tick(clipTimeout, func(time.Time) tea.Msg { return clipExpiredMsg(token) }),
		)
	case "s":
		if !passstore.Available() {
			return v, failure("pass is not initialised on this machine")
		}
		if v.value == "" {
			return v, failure("nothing to store")
		}
		v.form = newPassFormGenerated(v.value, v.bits)
		v.form.rules, v.form.po = v.rules, v.po
	case "+", "=":
		if v.phrase {
			v.po.Words++
		} else {
			v.co.Length++
		}
		v.regen()
	case "-", "_":
		if v.phrase && v.po.Words > 3 {
			v.po.Words--
		} else if !v.phrase && v.co.Length > 8 {
			v.co.Length--
		}
		v.regen()
	case "d":
		if v.phrase {
			v.po.Number = !v.po.Number
		} else {
			v.co.Digits = !v.co.Digits
		}
		v.regen()
	case "u":
		if v.phrase {
			v.po.Capitals = !v.po.Capitals
		} else {
			v.co.Upper = !v.co.Upper
		}
		v.regen()
	case "y":
		if v.phrase {
			switch v.po.Separator {
			case "-":
				v.po.Separator = "."
			case ".":
				v.po.Separator = "_"
			default:
				v.po.Separator = "-"
			}
		} else {
			v.co.Symbols = !v.co.Symbols
		}
		v.regen()
	case "x":
		if !v.phrase {
			v.co.SymbolsAll = !v.co.SymbolsAll
			v.regen()
		}
	case "a":
		if !v.phrase {
			v.co.NoAmbig = !v.co.NoAmbig
			v.regen()
		}
	}
	return v, nil
}

func (v *genView) Render(w, h int) string {
	if v.form != nil {
		return v.form.render(w)
	}
	if v.offer {
		var b strings.Builder
		b.WriteString(stAccent.Render("  Before the first password") + "\n\n")
		b.WriteString(stDim.Render(
			"  A printed sheet can hide what it carries: some characters on the page are\n"+
				"  noise to be deleted, and one stands for something only you remember. It is\n"+
				"  the backup that survives a lost machine and a forgotten master password.\n\n"+
				"  It has to be decided now, because it cannot be applied backwards. Passwords\n"+
				"  made before there is a rule can never go onto a masked sheet.\n\n") +
			stFg.Render("  [y]") + stDim.Render(" set it up      ") +
			stFg.Render("  any other key") + stDim.Render(" carry on without one") + "\n\n" +
			stDim.Render("  Not asked again this session either way."))
		return stBox.Width(w - 2).Render(b.String())
	}

	var b strings.Builder
	mode := "word phrase"
	if !v.phrase {
		mode = "random characters"
	}
	b.WriteString("  " + stDim.Render("mode: ") + stAccent.Render(mode) + "\n\n")

	if v.err != "" {
		b.WriteString(stErr.Render("  " + v.err))
		return b.String()
	}
	if v.value == "" {
		return b.String() + stDim.Render("  [r] makes one")
	}

	shown := mask(v.value)
	if v.rev.on {
		shown = v.value
	}
	b.WriteString(indent(stBox.Render(stFg.Render(shown)), 2) + "\n\n")

	// Said plainly, because the value now contains a piece the user chose and would otherwise
	// wonder about seeing in a "random" password. Worded without naming the rule: it holds
	// equally on a machine that has none, where there is simply nothing extra in there.
	if v.carriesRemembered {
		b.WriteString("  " + stDim.Render("part of this is the piece you remember — it is what keeps the sheet from being enough") + "\n\n")
	}

	label, detail := passgen.Strength(v.bits)
	st := stGood
	switch label {
	case "weak":
		st = stBad
	case "acceptable":
		st = stWarn
	}
	b.WriteString("  " + st.Render(label) + stDim.Render("  ·  "+detail) + "\n\n")

	if v.phrase {
		b.WriteString(fmt.Sprintf("  %s %d   %s %q   %s %s   %s %s\n",
			stDim.Render("words"), v.po.Words,
			stDim.Render("separator"), v.po.Separator,
			stDim.Render("capitals"), onoff(v.po.Capitals),
			stDim.Render("digits"), onoff(v.po.Number)))
		b.WriteString(stDim.Render(fmt.Sprintf("  word list: %d words → %.1f bits per word",
			passgen.WordCount(), v.bits/float64(maxi(v.po.Words, 1)))) + "\n")
	} else {
		b.WriteString(fmt.Sprintf("  %s %d   %s %s   %s %s   %s %s   %s %s\n",
			stDim.Render("length"), v.co.Length,
			stDim.Render("UPPER"), onoff(v.co.Upper),
			stDim.Render("digits"), onoff(v.co.Digits),
			stDim.Render("symbols"), onoff(v.co.Symbols),
			stDim.Render("all symbols"), onoff(v.co.SymbolsAll)))
		// The set is READ from the generator rather than typed here, so the two cannot drift
		// apart again.
		b.WriteString("  " + stDim.Render("no ambiguous ("+v.ambiguous()+"): ") + onoff(v.co.NoAmbig) + "\n")
	}

	b.WriteString("\n" + stNote.Render("  A word phrase is the better choice for a key passphrase:") + "\n")
	b.WriteString(stDim.Render("  it is long, it is memorable, and once you show it with [v] a wrong\n"+
		"  keyboard layout is obvious at a glance — unlike a string behind asterisks.") + "\n")

	return b.String()
}

func (v *genView) Footer() string {
	if v.form != nil {
		return v.form.footer()
	}
	if v.offer {
		return joinHints(hint("y", "set it up"), hint("other", "carry on"))
	}
	// The keys differ by mode and so must the hints. A footer written for one of them and
	// left alone is how [x] and [a] came to exist without ever being mentioned: the settings
	// were on screen, the way to change them was not.
	base := []string{hint("r", "new"), revealHint(v.rev.on), hint("m", "mode"), hint("c", "copy"), hint("+/-", "length")}
	if v.phrase {
		base = append(base, hint("u", "capitals"), hint("d", "digits"), hint("y", "separator"))
	} else {
		base = append(base,
			hint("u", "UPPER"), hint("d", "digits"), hint("y", "symbols"),
			hint("x", "all symbols"), hint("a", "no ambiguous"))
	}
	if passstore.Available() {
		base = append(base, hint("s", "to pass"))
	}
	return joinHints(base...)
}

func onoff(b bool) string {
	if b {
		return stGood.Render("yes")
	}
	return stDim.Render("no")
}

func maxi(a, b int) int {
	if a > b {
		return a
	}
	return b
}
