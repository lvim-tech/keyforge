package ui

import (
	"fmt"
	"os/exec"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/lvim-tech/keyforge/internal/config"
)

// view is one tab. Each owns its state and its own key handling; the shell below only routes.
type view interface {
	Init() tea.Cmd
	Update(tea.Msg) (view, tea.Cmd)
	Render(width, height int) string
	Title() string
	Footer() string
}

// statusMsg carries a one-line result to the shell's status bar.
type statusMsg struct {
	text string
	err  bool
}

func status(format string, a ...any) tea.Cmd {
	return func() tea.Msg { return statusMsg{text: fmt.Sprintf(format, a...)} }
}

func failure(format string, a ...any) tea.Cmd {
	return func() tea.Msg { return statusMsg{text: fmt.Sprintf(format, a...), err: true} }
}

// openRuleMsg asks for the rule form, wherever it lives.
//
// The generator raises it and the print tab answers it. The offer belongs where the first
// password is made; the form belongs with the sheet it describes — and the message is what
// keeps one from having to know about the other.
type openRuleMsg struct{}

// forgetMsg tells every view to drop whatever it is holding in the clear.
//
// Sent when the lock closes. A lock that shuts the store while this process goes on holding a
// decrypted password or the printing rule is a lock that is lying — and with clear_agent set
// it would be holding secrets the AGENT has already forgotten, which is worse than never
// having locked.
type forgetMsg struct{}

// reloadMsg asks the active view to re-read the world after something changed it.
type reloadMsg struct{}

func reload() tea.Msg { return reloadMsg{} }

// execMsg hands a command the real terminal. Everything that may ask for a passphrase travels this
// way: the TUI suspends, ssh-keygen or gpg owns the screen, the secret is typed into that process
// and into nothing else. See internal/sys for why this is the only accepted path.
type execMsg struct {
	cmd  *exec.Cmd
	then string // status line shown when it returns
}

// execDone is delivered after the child process exits.
type execDone struct {
	err  error
	then string
}

// Model is the application shell: a tab strip, the active view, and a status line.
type Model struct {
	views  []view
	active int
	w, h   int
	status string
	stErr  bool
	quit   bool
	lock   lockState

	// rules is read on demand and held for as long as the config says. The views reach it
	// through the shell rather than each keeping their own, so there is one answer to "is the
	// rule currently in this process" and one place that admits to it.
	rules *ruleCache
}

// New builds the application with every tab this machine can support.
func New(c config.Config) Model {
	rules := newRuleCache(c)
	return Model{
		lock:  newLockState(c),
		rules: rules,
		views: []view{
			newKeysView(c),
			newGenView(c, rules),
			newPassView(c, rules),
			newPrintView(c, rules),
			newAuditView(),
			newGPGView(),
			newCertView(c.CertPaths),
			newSettingsView(c, rules),
		},
	}
}

func (m Model) Init() tea.Cmd {
	var cmds []tea.Cmd
	for _, v := range m.views {
		if c := v.Init(); c != nil {
			cmds = append(cmds, c)
		}
	}
	if m.lock.enabled() {
		cmds = append(cmds, lockTick())
	}
	return tea.Batch(cmds...)
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	// The lock is handled before anything else: while it is closed, nothing behind it may see a key
	// press, and no tab may act on one. Routing it later would mean every view growing its own
	// "unless locked" clause, and one of them eventually forgetting.
	switch msg := msg.(type) {
	case lockTickMsg:
		if m.lock.idleExpired(time.Time(msg)) {
			m.lock.lock(fmt.Sprintf("no key pressed for %s", short(m.lock.idle)))
			m.status = ""
			return m, tea.Batch(lockTick(), m.afterLock())
		}
		return m, lockTick()

	case unlockDoneMsg:
		m.lock.unlocking = false
		if msg.err != nil {
			m.lock.err = m.lock.failedWith(msg.err)
			return m, nil
		}
		m.lock.unlocked()
		// The world may have moved on while the screen was covered.
		return m, func() tea.Msg { return reloadMsg{} }
	}

	if m.lock.locked {
		// The size arrives as its own message and is not a key press, so it has to be taken
		// before the filter below. Dropping it left the curtain with no width to draw
		// itself into, and View fell back to its "not sized yet" placeholder for ever: a
		// lock that opened onto a single "…" and no way to guess what was wanted.
		if size, ok := msg.(tea.WindowSizeMsg); ok {
			m.w, m.h = size.Width, size.Height
			return m, nil
		}
		key, ok := msg.(tea.KeyMsg)
		if !ok {
			return m, nil
		}
		switch key.String() {
		case "enter":
			if m.lock.unlocking {
				return m, nil
			}
			return m, m.lock.unlockCmd()
		case "q", "ctrl+c":
			// Quitting from the curtain still has to tidy up: the challenge is only ciphertext of a
			// fixed string, but a file per lock left in /dev/shm is litter with an alarming name.
			m.lock.clearChallenge()
			m.quit = true
			return m, tea.Quit
		}
		return m, nil
	}

	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.w, m.h = msg.Width, msg.Height
		return m, nil

	case statusMsg:
		m.status, m.stErr = msg.text, msg.err
		return m, nil

	case reloadMsg:
		return m, m.broadcast(msg)

	case openRuleMsg:
		// Move to the tab that owns the form, then hand it the message.
		for i, v := range m.views {
			if v.Title() == "Print" {
				m.active = i
			}
		}
		return m, m.broadcast(msg)

	case execMsg:
		then := msg.then
		return m, tea.ExecProcess(msg.cmd, func(err error) tea.Msg {
			return execDone{err: err, then: then}
		})

	case execDone:
		if msg.err != nil {
			// A non-zero exit is usually the user pressing Ctrl-C at a passphrase prompt or
			// getting it wrong — not something to shout about, but not something to hide either.
			m.status, m.stErr = "cancelled or failed: "+msg.err.Error(), true
		} else if msg.then != "" {
			m.status, m.stErr = msg.then, false
		}
		// The world changed under us; every view re-reads on the next tick.
		return m, func() tea.Msg { return reloadMsg{} }

	case tea.KeyMsg:
		m.lock.touch()
		// The on-demand lock is checked before the fixed keys, because it is configurable and the
		// user is entitled to bind it to something this shell would otherwise have swallowed.
		// Locking by hand is the case that actually gets used: you are leaving the desk now, not in
		// however many minutes the idle timer says.
		if k := m.lock.hotkey(); k != "" && msg.String() == k {
			if !m.lock.available() {
				return m, failure("no GPG key to unlock against — the lock needs one")
			}
			m.lock.lock("locked by hand")
			m.status = ""
			return m, tea.Batch(lockTick(), m.afterLock())
		}
		switch msg.String() {
		case "ctrl+c":
			m.rules.forget()
			m.quit = true
			return m, tea.Quit
		case "ctrl+f":
			if !m.rules.held() {
				return m, failure("nothing is being held")
			}
			m.rules.forget()
			return m, status("forgotten — the next generation or print will ask again")
		case "tab", "l", "right":
			if !m.viewCaptures() {
				m.active = (m.active + 1) % len(m.views)
				m.status = ""
				return m, nil
			}
		case "shift+tab", "h", "left":
			if !m.viewCaptures() {
				m.active = (m.active - 1 + len(m.views)) % len(m.views)
				m.status = ""
				return m, nil
			}
		case "q":
			if !m.viewCaptures() {
				m.quit = true
				return m, tea.Quit
			}
		}
	}

	// Routing rule, and it is the whole of it: KEYS go to the tab you are looking at, EVERYTHING
	// ELSE goes to every tab. A key press is aimed by the person pressing it; a loaded result is
	// aimed at whoever asked for it, and the tab that asked is usually not the one on screen —
	// every view starts its scan at startup, so the answers arrive while tab one is still showing.
	// Routing those to the active tab only is why the audit sat on "checking…" forever.
	if _, isKey := msg.(tea.KeyMsg); isKey {
		v, cmd := m.views[m.active].Update(msg)
		m.views[m.active] = v
		return m, cmd
	}
	return m, m.broadcast(msg)
}

// afterLock decides what the lock takes with it.
//
// The screen is covered and whatever is on it goes — a revealed password behind a curtain is
// a revealed password. The RULE cache is different and deliberately survives: the lock guards
// the screen against somebody walking past, while the cache spares the user a passphrase on
// every generated password. Locking for five minutes should not cost a re-entry, and the
// unlock proves exactly what filling the cache proved in the first place.
//
// The exception is clear_agent. There the lock has just told gpg-agent to forget, so keyforge
// holding the decrypted rule would mean keeping something the system has already released —
// the program saying one thing and doing another.
func (m *Model) afterLock() tea.Cmd {
	if m.lock.clearAgent {
		m.rules.forget()
	}
	return m.broadcast(forgetMsg{})
}

// broadcast delivers a message to every view and batches whatever they ask for in return.
func (m *Model) broadcast(msg tea.Msg) tea.Cmd {
	var cmds []tea.Cmd
	for i, v := range m.views {
		nv, c := v.Update(msg)
		m.views[i] = nv
		if c != nil {
			cmds = append(cmds, c)
		}
	}
	return tea.Batch(cmds...)
}

// viewCaptures reports whether the active view is in a mode where plain letters are text input
// rather than navigation — otherwise typing a filename would flip tabs on every "l".
func (m Model) viewCaptures() bool {
	if c, ok := m.views[m.active].(interface{ capturesInput() bool }); ok {
		return c.capturesInput()
	}
	return false
}

// splitHints takes a view's joined footer back apart.
//
// The seam is the two spaces joinHints puts between entries; the single space inside "[k]
// label" is never one. Taking the string apart rather than changing every view's Footer to
// return a slice keeps the change where the problem is — one line that was too long.
func splitHints(s string) []string {
	var out []string
	for _, p := range strings.Split(s, "  ") {
		if strings.TrimSpace(p) != "" {
			out = append(out, strings.TrimSpace(p))
		}
	}
	return out
}

// wrapHints lays the footer out across as many lines as it needs.
//
// It used to be one line, and a line that does not fit is not merely untidy: the hints that
// fall off the end are the ones nobody discovers. That is how [x] and [a] in the generator
// went unmentioned for as long as they did — the setting was on screen and the way to change
// it was past the edge.
//
// Measured with lipgloss.Width, not len: every hint carries colour, and the escape codes
// would otherwise be counted as characters and each line cut a third short.
func wrapHints(parts []string, width int) string {
	if width < 20 {
		width = 20
	}
	var lines []string
	cur, curW := "", 0
	for _, p := range parts {
		w := lipgloss.Width(p)
		switch {
		case cur == "":
			cur, curW = p, w
		case curW+2+w <= width:
			cur, curW = cur+"  "+p, curW+2+w
		default:
			lines = append(lines, cur)
			cur, curW = p, w
		}
	}
	if cur != "" {
		lines = append(lines, cur)
	}
	for i, l := range lines {
		lines[i] = stFooter.Render(l)
	}
	return strings.Join(lines, "\n")
}

// tabStrip draws the tabs, narrowing them until they fit rather than running off the edge.
//
// Three widths, tried in order: full titles; titles without the padding; then only the tab
// you are on, with a count of the rest. A strip that overflows does not merely look wrong —
// it pushes the last tabs off the screen, and a tab you cannot see is a tab you do not know
// exists. Eight of them stopped fitting an 80-column terminal, which is the ordinary size.
func (m Model) tabStrip(avail int) string {
	full, tight := 0, 0
	for _, v := range m.views {
		full += len([]rune(v.Title())) + 4
		tight += len([]rune(v.Title())) + 1
	}

	var b strings.Builder
	switch {
	case full <= avail:
		for i, v := range m.views {
			if i == m.active {
				b.WriteString(stTabOn.Render(v.Title()))
			} else {
				b.WriteString(stTab.Render(v.Title()))
			}
		}
	case tight <= avail:
		for i, v := range m.views {
			if i == m.active {
				b.WriteString(stTabOn.Render(v.Title()))
			} else {
				b.WriteString(stTabTight.Render(v.Title()))
			}
			if i < len(m.views)-1 {
				b.WriteString(" ")
			}
		}
	default:
		// Nothing else fits. Naming where you are beats showing a row that has been cut off
		// at an arbitrary point, which reads as though the missing tabs do not exist.
		b.WriteString(stTabOn.Render(m.views[m.active].Title()))
		b.WriteString(stDim.Render(fmt.Sprintf("  %d/%d  tab moves", m.active+1, len(m.views))))
	}
	return b.String()
}

func (m Model) View() string {
	if m.quit {
		return ""
	}
	if m.w == 0 {
		return "…"
	}
	if m.lock.locked {
		return stTitle.Render("keyforge") + "\n" +
			m.lock.render(m.w, m.h-3) + "\n" + stFooter.Render(m.lock.footer())
	}

	head := stTitle.Render("keyforge") + " " + m.tabStrip(m.w-len("keyforge "))

	st := ""
	if m.status != "" {
		if m.stErr {
			st = stErr.Render("✕ " + m.status)
		} else {
			st = stOK.Render("✓ " + m.status)
		}
	}

	shell := []string{hint("tab", "next tab"), hint("q", "quit")}
	if m.rules.held() {
		shell = append(shell, hint("ctrl+f", "forget"))
	}
	if m.lock.available() && m.lock.hotkey() != "" {
		shell = append(shell, hint(m.lock.hotkey(), "lock"))
	}
	all := append(shell, splitHints(m.views[m.active].Footer())...)
	if s := m.lock.status(); s != "" {
		all = append(all, s)
	}
	foot := wrapHints(all, m.w-2)

	// Said in red for as long as it is true. This is keyforge's own cache, not the agent's:
	// a program that quietly held a decrypted secret for an hour while showing nothing would
	// be doing the very thing it exists to expose.
	//
	// Added BEFORE the height is worked out, not after. Prepending it afterwards made the
	// composed view one row taller than the terminal every time it showed — and under the
	// alternate screen the row that falls off the bottom is the footer, so the warning about
	// the held rule pushed the keys for dealing with it out of sight.
	if w := m.rules.warning(); w != "" {
		foot = stErr.Render("● "+w) + "\n" + foot
	}

	// The footer is built first, because how many rows it wants decides what is left for the
	// body. Assuming one line and then drawing three is how a list loses its last entries off
	// the bottom of the screen.
	footLines := strings.Count(foot, "\n") + 1
	bodyH := m.h - 4 - footLines
	if bodyH < 3 {
		bodyH = 3
	}
	body := m.views[m.active].Render(m.w, bodyH)

	return head + "\n\n" + body + "\n" + st + "\n" + foot
}
