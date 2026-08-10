package ui

import (
	"fmt"
	"os/exec"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"

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
}

// New builds the application with every tab this machine can support.
func New(c config.Config) Model {
	return Model{
		lock: newLockState(c),
		views: []view{
			newKeysView(),
			newGenView(),
			newPassView(),
			newPrintView(),
			newAuditView(),
			newGPGView(),
			newCertView(),
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
		}
		return m, lockTick()

	case unlockDoneMsg:
		m.lock.unlocking = false
		if msg.err != nil {
			m.lock.err = "not unlocked: " + msg.err.Error()
			return m, nil
		}
		m.lock.unlocked()
		// The world may have moved on while the screen was covered.
		return m, func() tea.Msg { return reloadMsg{} }
	}

	if m.lock.locked {
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
		switch msg.String() {
		case "ctrl+c":
			m.quit = true
			return m, tea.Quit
		case "ctrl+l":
			// Locking by hand is the case that actually gets used: you are leaving the desk now, not
			// in however many minutes the idle timer says.
			if !m.lock.available() {
				return m, failure("no GPG key to unlock against — the lock needs one")
			}
			m.lock.lock("locked by hand")
			m.status = ""
			return m, lockTick()
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

	var tabs []string
	for i, v := range m.views {
		if i == m.active {
			tabs = append(tabs, stTabOn.Render(v.Title()))
		} else {
			tabs = append(tabs, stTab.Render(v.Title()))
		}
	}
	head := stTitle.Render("keyforge") + " " + strings.Join(tabs, "")

	// 1 head + 1 blank + body + 1 blank + 1 status + 1 footer
	bodyH := m.h - 5
	if bodyH < 3 {
		bodyH = 3
	}
	body := m.views[m.active].Render(m.w, bodyH)

	st := ""
	if m.status != "" {
		if m.stErr {
			st = stErr.Render("✕ " + m.status)
		} else {
			st = stOK.Render("✓ " + m.status)
		}
	}

	shell := []string{hint("tab", "next tab"), hint("q", "quit")}
	if m.lock.available() {
		shell = append(shell, hint("ctrl+l", "lock"))
	}
	foot := stFooter.Render(joinHints(shell...) + "   " + m.views[m.active].Footer())
	if s := m.lock.status(); s != "" {
		foot += stFooter.Render("   " + s)
	}

	return head + "\n\n" + body + "\n" + st + "\n" + foot
}
