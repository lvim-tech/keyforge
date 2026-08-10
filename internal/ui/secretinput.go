package ui

import (
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/lvim-tech/keyforge/internal/sys"
)

// secretInput is a text field for a value that must not appear on screen or in the Go heap.
//
// It is a separate type from `input` on purpose. The ordinary field keeps its contents in a []rune —
// convenient, and impossible to erase, because the garbage collector may have moved copies around
// long before anyone thinks to wipe it. This one writes straight into an mlocked, dump-excluded
// buffer and renders dots. The distinction is worth a second type: the compiler then makes it
// impossible to hold a passphrase in the wrong one by accident.
type secretInput struct {
	label string
	hint  string
	buf   *sys.Secret
	err   string
}

func newSecretInput(label, hint string) *secretInput {
	s := &secretInput{label: label, hint: hint}
	buf, err := sys.NewSecret(512)
	if err != nil {
		s.err = err.Error()
		return s
	}
	s.buf = buf
	return s
}

// update handles a key press, returning whether it was consumed.
func (s *secretInput) update(msg tea.KeyMsg) bool {
	if s.buf == nil {
		return false
	}
	switch msg.Type {
	case tea.KeyRunes:
		s.buf.Append([]byte(string(msg.Runes)))
		return true
	case tea.KeySpace:
		s.buf.Append([]byte(" "))
		return true
	case tea.KeyBackspace:
		s.buf.Backspace()
		return true
	case tea.KeyCtrlU:
		s.buf.Reset()
		return true
	}
	return false
}

func (s *secretInput) empty() bool { return s.buf == nil || s.buf.Empty() }

// secret exposes the locked buffer itself, for the two operations that must not go through a string:
// comparing a value against its confirmation, and writing it into `pass`.
func (s *secretInput) secret() *sys.Secret { return s.buf }

// set replaces the contents — used to drop a generated value into the field. The value arrives as a
// Go string because that is what the generator returns, so this one copy is already on the heap
// before it gets here; what it buys is that everything downstream reads the locked buffer instead.
func (s *secretInput) set(v string) {
	if s.buf == nil {
		return
	}
	s.buf.Set([]byte(v))
}

// use hands the value out for the moment it is needed. See sys.Secret.Use for why this is the one
// place where the guarantee is necessarily weaker.
func (s *secretInput) use(fn func(string)) {
	if s.buf == nil {
		fn("")
		return
	}
	s.buf.Use(fn)
}

func (s *secretInput) reset() {
	if s.buf != nil {
		s.buf.Reset()
	}
}

// close releases the locked buffer. Called when the form is done with the value.
func (s *secretInput) close() {
	if s.buf != nil {
		s.buf.Close()
		s.buf = nil
	}
}

// render draws dots, one per rune. The length is shown because a passphrase typed with the wrong
// keyboard layout usually comes out a different length, and that is the one clue a masked field can
// honestly give — everything else about it is, by design, invisible.
func (s *secretInput) render(focused bool) string {
	label := stDim.Render(s.label + ": ")
	if focused {
		label = stKey.Render(s.label + ": ")
	}
	if s.err != "" {
		return label + stErr.Render(s.err)
	}
	n := s.buf.Len()
	if n == 0 {
		if focused {
			return label + stRowSel.Render(" ")
		}
		return label + stDim.Render(s.hint)
	}
	dots := strings.Repeat("•", n)
	if focused {
		dots += stRowSel.Render(" ")
	}
	body := stFg.Render(dots)
	lock := ""
	if s.buf.Locked() {
		lock = stDim.Render("   locked memory")
	} else {
		lock = stWarn.Render("   memory is NOT locked")
	}
	return label + body + stDim.Render("  ("+itoa(n)+")") + lock
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [8]byte
	i := len(b)
	for n > 0 && i > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
