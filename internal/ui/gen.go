package ui

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/lvim-tech/keyforge/internal/passgen"
	"github.com/lvim-tech/keyforge/internal/passstore"
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
}

func newGenView() *genView {
	v := &genView{
		phrase: true,
		po:     passgen.DefaultPhraseOptions(),
		co:     passgen.DefaultOptions(),
	}
	v.regen()
	return v
}

func (v *genView) Title() string { return "Generator" }

func (v *genView) capturesInput() bool { return v.form != nil }

func (v *genView) Init() tea.Cmd { return nil }

func (v *genView) regen() {
	var err error
	if v.phrase {
		v.value, v.bits, err = passgen.Phrase(v.po)
	} else {
		v.value, v.bits, err = passgen.Password(v.co)
	}
	if err != nil {
		v.err = err.Error()
		v.value = ""
	} else {
		v.err = ""
	}
}

func (v *genView) Update(msg tea.Msg) (view, tea.Cmd) {
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

	switch key.String() {
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
		return v, status("copied — paste it into ssh-keygen's own prompt")
	case "s":
		if !passstore.Available() {
			return v, failure("pass is not initialised on this machine")
		}
		if v.value == "" {
			return v, failure("nothing to store")
		}
		v.form = newPassFormGenerated(v.value, v.bits)
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

	b.WriteString(indent(stBox.Render(stFg.Render(v.value)), 2) + "\n\n")

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
		b.WriteString("  " + stDim.Render("no ambiguous (0O1lI): ") + onoff(v.co.NoAmbig) + "\n")
	}

	b.WriteString("\n" + stNote.Render("  A word phrase is the better choice for a key passphrase:") + "\n")
	b.WriteString(stDim.Render("  it is long, it is memorable, and a wrong keyboard layout shows\n"+
		"  at once — unlike a string hidden behind asterisks.") + "\n")

	return b.String()
}

func (v *genView) Footer() string {
	if v.form != nil {
		return v.form.footer()
	}
	base := []string{
		hint("r", "new"), hint("m", "mode"), hint("c", "copy"),
		hint("+/-", "length"), hint("u", "capitals"), hint("d", "digits"), hint("y", "separator"),
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
