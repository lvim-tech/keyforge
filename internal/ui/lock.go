package ui

import (
	"fmt"
	"os"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/lvim-tech/keyforge/internal/config"
	"github.com/lvim-tech/keyforge/internal/gpgkeys"
	"github.com/lvim-tech/keyforge/internal/passstore"
)

// lockState is the screen lock: keyforge covered over, opened by proving you can use the GPG key
// that `pass` encrypts to.
//
// WHAT IT IS AND WHAT IT IS NOT. keyforge holds none of the data it shows — `pass` does, and
// `~/.ssh` does — so a lock over this interface cannot stop anyone who can reach the account; they
// would simply run `pass show`. Sold as protection of the store, it would be a lie. What it
// genuinely covers is the case it was asked for: an unlocked terminal that has been walked away
// from, where the tree, the clipboard and the edit keys are one keypress away.
//
// That is also why locking clears the agent. A lock whose unlock prompt never appears — because gpg
// still has the passphrase cached and signs without asking — is a curtain, not a lock. Clearing the
// cache first makes the prompt real, and has the side effect of genuinely shutting the store: after
// locking, `pass show` in another terminal asks too. That side effect is the only reason this is
// worth more than hiding the screen, which is why it is on by default and configurable rather than
// silently skipped.
type lockState struct {
	// enabled and idle come from the config; a zero idle means the lock was never asked for.
	idle       time.Duration
	clearAgent bool
	key        string // the on-demand lock key, "" for none

	locked bool
	// unlocking is set while gpg has the terminal, so the tick does not re-lock underneath it.
	unlocking bool
	last      time.Time // when a key was last pressed

	recipient string // the GPG key the store encrypts to
	challenge string // ciphertext only that key can open; the unlock is opening it
	// gpgErr collects what gpg said while it had the terminal, so a refusal can be reported as the
	// reason it happened rather than as a number.
	gpgErr *strings.Builder
	reason string // why it locked, shown on the curtain
	err    string
}

// lockTickMsg drives the idle check.
type lockTickMsg time.Time

// lockTick is deliberately coarse. The lock is measured in minutes, so a second's granularity is
// already far finer than it needs, and a busier timer would wake the process for nothing.
func lockTick() tea.Cmd {
	return tea.Tick(time.Second, func(t time.Time) tea.Msg { return lockTickMsg(t) })
}

// unlockDoneMsg carries the result of the gpg run that opens the lock.
type unlockDoneMsg struct{ err error }

func newLockState(c config.Config) lockState {
	l := lockState{
		idle:       time.Duration(c.Lock.IdleMinutes) * time.Minute,
		clearAgent: c.Lock.ClearAgent,
		key:        strings.TrimSpace(c.Lock.Key),
		last:       time.Now(),
	}
	// The recipient is enough: the unlock decrypts, so it needs the key the store is encrypted TO,
	// not the key id of any particular subkey.
	if passstore.Available() {
		l.recipient = passstore.Recipient()
	}
	// Locked before anything is drawn, so the first thing seen is the curtain rather than a
	// list of entry names. The names are not the secret, but they are the list of every site
	// you have an account with, and that is not nothing.
	if c.Lock.AtStart && l.available() {
		l.lock("locked on opening")
	}
	return l
}

// available reports whether there is anything to unlock against. Without a GPG key there is no
// passphrase to prove knowledge of, and keyforge will not invent one to fill the gap.
func (l *lockState) available() bool { return l.recipient != "" }

// enabled reports whether the idle lock is configured and usable.
func (l *lockState) enabled() bool { return l.idle > 0 && l.available() }

// touch records activity. Called on every key press, which is the only signal a TUI has.
func (l *lockState) touch() { l.last = time.Now() }

// lock closes the curtain and, when configured, makes the agent forget — which is what turns the
// unlock prompt from theatre into a question that has to be answered.
func (l *lockState) lock(reason string) {
	if l.locked {
		return
	}
	// Built before the cache is cleared, because encrypting needs no passphrase and a lock that
	// cannot produce its own challenge would be a lock with no key.
	//
	// IT LOCKS EITHER WAY. This used to return here, leaving `locked` false and the reason in
	// `l.err` — which is rendered on the curtain, the very thing that was not drawn. The caller
	// then cleared the status line and wiped the views, so the idle timer would fire, nothing
	// would happen, and the screen stayed open with the passwords on it. Failing open is the
	// one outcome a lock may not have, and it failed open in silence.
	//
	// A curtain with no challenge cannot be opened by [enter] — unlockCmd says so plainly —
	// but it can always be left by [q], which quits cleanly. Covered and escapable beats
	// uncovered and confident.
	ch, err := gpgkeys.NewChallenge(l.recipient)
	l.clearChallenge()
	l.challenge = ch
	l.locked, l.reason, l.err = true, reason, ""
	if err != nil {
		l.err = "no unlock challenge could be made: " + err.Error() + " — [q] quits"
	}

	if !l.clearAgent {
		return
	}
	if cerr := gpgkeys.ClearCache(); cerr != nil {
		// Worth saying out loud: the lock is now weaker than it claims, and silence here would be
		// the difference between a lock and a picture of one. Appended rather than assigned, so
		// it cannot erase the missing-challenge line above.
		if l.err != "" {
			l.err += "; "
		}
		l.err += "the agent was not cleared: " + cerr.Error()
	}
}

// clearChallenge removes the ciphertext scrap. It is not a secret — it is a message to yourself —
// but a file left in /dev/shm for every lock of every session is litter with a name that invites
// questions.
func (l *lockState) clearChallenge() {
	if l.challenge != "" {
		_ = os.Remove(l.challenge)
		l.challenge = ""
	}
}

// unlocked is called once gpg has proved the passphrase was supplied.
func (l *lockState) unlocked() {
	l.clearChallenge()
	l.locked, l.err = false, ""
	l.touch()
}

// idleExpired reports whether enough quiet has passed to lock.
func (l *lockState) idleExpired(now time.Time) bool {
	return l.enabled() && !l.locked && !l.unlocking && now.Sub(l.last) >= l.idle
}

// unlockCmd hands gpg the terminal. keyforge learns only whether the exit code was zero; the
// passphrase is typed into pinentry and lives in gpg, exactly as everywhere else in this program.
func (l *lockState) unlockCmd() tea.Cmd {
	if l.challenge == "" {
		return failure("there is no unlock challenge — locking failed to make one")
	}
	l.unlocking = true
	l.gpgErr = &strings.Builder{}
	cmd := gpgkeys.UnlockCmd(l.challenge, l.gpgErr)
	return tea.ExecProcess(cmd, func(err error) tea.Msg { return unlockDoneMsg{err: err} })
}

// failedWith turns a non-zero exit into something worth reading.
func (l *lockState) failedWith(err error) string {
	said := ""
	if l.gpgErr != nil {
		for _, line := range strings.Split(strings.TrimSpace(l.gpgErr.String()), "\n") {
			line = strings.TrimSpace(line)
			// gpg narrates every step; only its complaints are of any use here.
			if strings.HasPrefix(line, "gpg: ") && !strings.Contains(line, "encrypted with") {
				said = strings.TrimPrefix(line, "gpg: ")
			}
		}
	}
	if said == "" {
		return "not unlocked: " + err.Error()
	}
	return "not unlocked: " + said
}

// render draws the curtain. Nothing of the interface behind it is drawn — a lock that leaves the
// password tree legible underneath has locked the keyboard and nothing else.
func (l lockState) render(w, h int) string {
	var b strings.Builder
	b.WriteString(stAccent.Render("  keyforge is locked") + "\n\n")
	if l.reason != "" {
		b.WriteString(stDim.Render("  "+l.reason) + "\n\n")
	}
	b.WriteString("  " + stKey.Render("[enter]") + stDim.Render(" unlock") +
		stDim.Render("      ") + stKey.Render("[q]") + stDim.Render(" quit") + "\n\n")

	if l.clearAgent {
		b.WriteString(stDim.Render("  The gpg agent was cleared, so this asks for the passphrase of the key\n" +
			"  the store is encrypted to — and everything else that wants the store\n" +
			"  will ask again too. Locking keyforge shut the store, not just the screen."))
	} else {
		b.WriteString(stWarn.Render("  The agent was left holding the passphrase (lock.clear_agent = false),\n" +
			"  so this will open without asking for anything. It hides the screen and\n" +
			"  nothing more."))
	}
	if l.err != "" {
		b.WriteString("\n\n" + stErr.Render("  "+l.err))
	}

	body := stBox.Width(w - 2).Render(b.String())
	// Pushed down the screen so the curtain reads as covering it rather than as one more panel.
	pad := (h - strings.Count(body, "\n") - 1) / 2
	if pad < 1 {
		pad = 1
	}
	return strings.Repeat("\n", pad) + body
}

func (l lockState) footer() string {
	return joinHints(hint("enter", "unlock"), hint("q", "quit"))
}

// hotkey reports the on-demand lock key, or "" when none is configured.
func (l lockState) hotkey() string { return l.key }

// lockStatus is the one-line summary for the interface, so the setting is visible rather than a
// thing that happens to you.
func (l lockState) status() string {
	switch {
	case !l.available():
		return ""
	case l.idle <= 0:
		return stDim.Render("lock off")
	default:
		return stDim.Render(fmt.Sprintf("locks after %s", short(l.idle)))
	}
}
