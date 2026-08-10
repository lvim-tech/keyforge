package ui

import (
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
)

// reveal is the single rule for putting a secret on screen, shared by every tab that holds one.
//
// The rule is: masked until asked, visible for a while, then masked again. It lives in one type
// because it was previously three different behaviours — the generator printed its value in the
// clear and never stopped, the print sheet had a toggle with no timer, and the password list had no
// way at all. A password on screen is a password in whatever is looking at the screen, and which
// tab produced it does not change that.
//
// The token is what makes the timer safe. Reveal something, hide it, reveal it again: the first
// timer is still in flight and would otherwise hide the second value early, or worse, wipe a buffer
// that has since been replaced. Every reveal takes a new token and a hide only lands if the tokens
// still match.
type reveal struct {
	on    bool
	token int

	// onHide wipes whatever the view is holding, for the views whose secret is a locked buffer
	// rather than a value they already have in hand.
	onHide func()
}

// revealTimeout is how long a secret stays visible. Long enough to read it across to a phone or a
// browser, short enough that walking away from the terminal does not leave it there.
const revealTimeout = 30 * time.Second

// revealTokens hands out the tokens. Package-level because messages are broadcast to every tab, so
// tokens have to be unique across all of them, not just within one.
var revealTokens int

// hideRevealMsg is delivered when a reveal has run its course.
type hideRevealMsg struct{ token int }

// show turns the secret on and returns the command that will turn it off again.
func (r *reveal) show() tea.Cmd {
	revealTokens++
	r.on, r.token = true, revealTokens
	token := r.token
	return tea.Tick(revealTimeout, func(time.Time) tea.Msg {
		return hideRevealMsg{token: token}
	})
}

// hide turns it off now, running whatever the view needs to wipe.
func (r *reveal) hide() {
	if r.onHide != nil {
		r.onHide()
	}
	r.on = false
	// A new token, so any timer still in flight for the old one lands on nothing.
	revealTokens++
	r.token = revealTokens
}

// toggle is what the [v] key calls. It returns a command only when something was turned on.
func (r *reveal) toggle() tea.Cmd {
	if r.on {
		r.hide()
		return nil
	}
	return r.show()
}

// expired reports whether this message is the timer for what is currently shown, and hides it if so.
func (r *reveal) expired(msg tea.Msg) bool {
	m, ok := msg.(hideRevealMsg)
	if !ok || !r.on || m.token != r.token {
		return false
	}
	r.hide()
	return true
}

// mask renders a value as dots of the same length.
//
// The length is shown rather than a fixed run of dots because it is the one thing a mask can give
// away without giving anything away — and it is what tells you the value is there at all.
func mask(s string) string {
	return strings.Repeat("•", len([]rune(s)))
}

// revealHint is the footer entry, worded so it says which way it is about to go.
func revealHint(on bool) string {
	if on {
		return hint("v", "hide")
	}
	return hint("v", "reveal")
}
