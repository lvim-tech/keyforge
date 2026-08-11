package ui

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
)

// input is a one-line text field.
//
// Hand-rolled rather than pulled from a widget library for one reason that matters in this program:
// keyforge must never end up with a secret in a component whose lifetime it does not control. This
// field is used only for names, comments and hostnames — never for a passphrase, which goes
// straight into ssh-keygen's own prompt — and keeping it small makes that boundary easy to see.
type input struct {
	label  string
	value  []rune
	cursor int
	width  int
	hint   string

	// masked hides the contents behind dots.
	//
	// Used for the parts of the printing rule. They are not passwords, but they are the
	// legend of the paper: somebody who reads "q7" off this screen can turn a printed sheet
	// back into the password on it. A field that shows them while they are being chosen
	// undoes the point of storing them encrypted afterwards.
	masked bool
}

func newInput(label, hint string) input {
	return input{label: label, hint: hint, width: 40}
}

func newMaskedInput(label, hint string) input {
	return input{label: label, hint: hint, width: 40, masked: true}
}

func (i *input) set(s string) {
	i.value = []rune(s)
	i.cursor = len(i.value)
}

func (i input) String() string { return string(i.value) }

func (i input) empty() bool { return len(strings.TrimSpace(string(i.value))) == 0 }

// update handles a key press, returning whether it was consumed.
func (i *input) update(msg tea.KeyMsg) bool {
	switch msg.Type {
	case tea.KeyRunes:
		i.value = append(i.value[:i.cursor], append([]rune(string(msg.Runes)), i.value[i.cursor:]...)...)
		i.cursor += len(msg.Runes)
		return true
	case tea.KeySpace:
		i.value = append(i.value[:i.cursor], append([]rune{' '}, i.value[i.cursor:]...)...)
		i.cursor++
		return true
	case tea.KeyBackspace:
		if i.cursor > 0 {
			i.value = append(i.value[:i.cursor-1], i.value[i.cursor:]...)
			i.cursor--
		}
		return true
	case tea.KeyDelete:
		if i.cursor < len(i.value) {
			i.value = append(i.value[:i.cursor], i.value[i.cursor+1:]...)
		}
		return true
	case tea.KeyLeft:
		if i.cursor > 0 {
			i.cursor--
		}
		return true
	case tea.KeyRight:
		if i.cursor < len(i.value) {
			i.cursor++
		}
		return true
	case tea.KeyHome, tea.KeyCtrlA:
		i.cursor = 0
		return true
	case tea.KeyEnd, tea.KeyCtrlE:
		i.cursor = len(i.value)
		return true
	case tea.KeyCtrlU:
		i.value, i.cursor = nil, 0
		return true
	}
	return false
}

// render draws the field, marking the cursor position and showing the hint when empty.
func (i input) render(focused bool) string {
	if i.masked {
		label := stDim.Render(i.label + ": ")
		if focused {
			label = stKey.Render(i.label + ": ")
		}
		if len(i.value) == 0 {
			if focused {
				return label + stRowSel.Render(" ")
			}
			return label + stDim.Render(i.hint)
		}
		// One dot per CHARACTER and the count beside it — the same honesty the passphrase
		// field owes: a mask that counts bytes says nothing true about what was typed.
		dots := strings.Repeat("•", len(i.value))
		if focused {
			dots += stRowSel.Render(" ")
		}
		return label + stFg.Render(dots) + stDim.Render(fmt.Sprintf("  (%d)", len(i.value)))
	}
	text := string(i.value)
	if text == "" && !focused {
		text = stDim.Render(i.hint)
	} else if focused {
		before, after := string(i.value[:i.cursor]), string(i.value[i.cursor:])
		cur := " "
		if i.cursor < len(i.value) {
			cur = string(i.value[i.cursor])
			after = string(i.value[i.cursor+1:])
		}
		text = before + stRowSel.Render(cur) + after
	}
	label := stDim.Render(i.label + ": ")
	if focused {
		label = stKey.Render(i.label + ": ")
	}
	return label + text
}
