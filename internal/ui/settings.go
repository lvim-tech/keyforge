package ui

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/lvim-tech/keyforge/internal/config"
	"github.com/lvim-tech/keyforge/internal/gpgkeys"
	"github.com/lvim-tech/keyforge/internal/passstore"
)

// settingsView is for the settings that have nowhere else to live.
//
// The test for belonging here is narrow and worth stating, because a settings screen with no
// test becomes a drawer: something is a setting if it is PERSISTENT, INVISIBLE, and not
// adjustable where its effect can be seen. The password length is none of those — it is
// adjusted in the Generator with +/- while the result changes in front of you, and moving it
// here would make it worse. What is here is the opposite: numbers that decide how long a
// passphrase stays unlocked on this machine, which govern everything and could until now only
// be changed by hand-editing JSON.
//
// The agent's lifetimes are shown beside what they are currently DOING. A number without its
// state is half the information, and this program's whole business is the other half.
type settingsView struct {
	cfg   config.Config
	rules *ruleCache

	sel     int
	editing bool
	buf     input
	dirty   bool
	note    string

	// agent state, refreshed with the tab rather than on every draw: it costs a process.
	cached  bool
	ttl     gpgkeys.CacheTTL
	checked time.Time
}

type settingKind int

const (
	skInt settingKind = iota
	skBool
	skKey
)

type setting struct {
	label string
	kind  settingKind
	get   func(*settingsView) string
	set   func(*settingsView, string) error
	// note is shown under the selected row: what the setting costs, not what it is.
	note string
}

var settings = []setting{
	{
		label: "lock on opening",
		kind:  skBool,
		get:   func(v *settingsView) string { return yesno(v.cfg.Lock.AtStart) },
		set:   func(v *settingsView, _ string) error { v.cfg.Lock.AtStart = !v.cfg.Lock.AtStart; return nil },
		note:  "keyforge opens covered. Worth what the next setting makes it worth.",
	},
	{
		label: "lock after idle",
		kind:  skInt,
		get: func(v *settingsView) string {
			if v.cfg.Lock.IdleMinutes <= 0 {
				return "never"
			}
			return fmt.Sprintf("%d min", v.cfg.Lock.IdleMinutes)
		},
		set: func(v *settingsView, s string) error {
			n, err := strconv.Atoi(strings.TrimSpace(s))
			if err != nil || n < 0 {
				return fmt.Errorf("minutes, or 0 for never")
			}
			v.cfg.Lock.IdleMinutes = n
			return nil
		},
		note: "0 means it only locks when you ask.",
	},
	{
		label: "locking clears the agent",
		kind:  skBool,
		get:   func(v *settingsView) string { return yesno(v.cfg.Lock.ClearAgent) },
		set:   func(v *settingsView, _ string) error { v.cfg.Lock.ClearAgent = !v.cfg.Lock.ClearAgent; return nil },
		note: "on: locking shuts the store for the whole machine — mail and signed commits ask again. " +
			"off: the curtain hides the screen and nothing more.",
	},
	{
		label: "lock key",
		kind:  skKey,
		get:   func(v *settingsView) string { return orNone(v.cfg.Lock.Key) },
		set: func(v *settingsView, s string) error {
			v.cfg.Lock.Key = strings.TrimSpace(s)
			return nil
		},
		note: "taken by the shell before any tab sees it, so it is taken away from that tab.",
	},
	{
		label: "agent forgets after idle",
		kind:  skInt,
		get:   func(v *settingsView) string { return secs(v.cfg.Agent.DefaultCacheTTL, "gpg's own 600") },
		set: func(v *settingsView, s string) error {
			n, err := strconv.Atoi(strings.TrimSpace(s))
			if err != nil || n < 0 {
				return fmt.Errorf("seconds, or 0 to leave gpg alone")
			}
			v.cfg.Agent.DefaultCacheTTL = n
			return nil
		},
		note: "restarts on every use, so during steady work it never expires.",
	},
	{
		label: "agent forgets regardless",
		kind:  skInt,
		get:   func(v *settingsView) string { return secs(v.cfg.Agent.MaxCacheTTL, "gpg's own 7200") },
		set: func(v *settingsView, s string) error {
			n, err := strconv.Atoi(strings.TrimSpace(s))
			if err != nil || n < 0 {
				return fmt.Errorf("seconds, or 0 to leave gpg alone")
			}
			v.cfg.Agent.MaxCacheTTL = n
			return nil
		},
		note: "the ceiling from when you typed it. This is the one that ever asks you again — " +
			"a passphrase never retyped is a passphrase eventually forgotten.",
	},
	{
		label: "keyforge keeps the sheet rule",
		kind:  skInt,
		get:   func(v *settingsView) string { return mins(v.cfg.Sheet.CacheMinutes) },
		set: func(v *settingsView, s string) error {
			n, err := strconv.Atoi(strings.TrimSpace(s))
			if err != nil || n < 0 {
				return fmt.Errorf("minutes, or 0 to ask every time")
			}
			v.cfg.Sheet.CacheMinutes = n
			return nil
		},
		note: "this one is keyforge's own memory, not the agent's — it says so in red while it holds.",
	},
}

func newSettingsView(c config.Config, rules *ruleCache) *settingsView {
	return &settingsView{cfg: c, rules: rules, buf: newInput("value", "")}
}

func (v *settingsView) Title() string { return "Settings" }

func (v *settingsView) capturesInput() bool { return v.editing }

func (v *settingsView) Init() tea.Cmd { return refreshAgent }

type agentState struct {
	cached bool
	ttl    gpgkeys.CacheTTL
}

func refreshAgent() tea.Msg {
	return agentState{cached: gpgkeys.AnyCached(), ttl: gpgkeys.AgentCacheTTL()}
}

func (v *settingsView) Update(msg tea.Msg) (view, tea.Cmd) {
	switch msg := msg.(type) {
	case agentState:
		v.cached, v.ttl, v.checked = msg.cached, msg.ttl, time.Now()
		return v, nil
	case reloadMsg:
		return v, refreshAgent
	case tea.KeyMsg:
		if v.editing {
			switch msg.String() {
			case "esc":
				v.editing = false
				return v, nil
			case "enter":
				if err := settings[v.sel].set(v, v.buf.String()); err != nil {
					return v, failure("%v", err)
				}
				v.editing, v.dirty = false, true
				return v, nil
			}
			v.buf.update(msg)
			return v, nil
		}
		switch msg.String() {
		case "j", "down":
			if v.sel < len(settings)-1 {
				v.sel++
			}
		case "k", "up":
			if v.sel > 0 {
				v.sel--
			}
		case "enter", " ":
			s := settings[v.sel]
			if s.kind == skBool {
				_ = s.set(v, "")
				v.dirty = true
				return v, nil
			}
			v.editing = true
			v.buf.set("")
		case "w":
			return v, v.save()
		}
	}
	return v, nil
}

// save writes both files, and says which of the two took effect immediately.
//
// They are different in a way worth surfacing: keyforge's own config is read at startup, so
// most of what is written here applies next time. The agent's lifetimes are written into
// gpg-agent.conf and take effect when the agent re-reads them — which also drops every
// cached passphrase, so the next mail or commit will ask. That is the reload, not a fault,
// and it is better said before it happens than discovered after.
func (v *settingsView) save() tea.Cmd {
	// The sections this tab OWNS, and not one field more. sheet.rule_from is set by Print and
	// was being erased from here: this view's copy was taken at startup, so its empty rule_from
	// went straight over the name of a rule entry created since — leaving a random-named entry
	// in the store that nothing points at any more.
	updated, err := config.Update(func(c *config.Config) {
		c.Lock = v.cfg.Lock
		c.Agent = v.cfg.Agent
		c.Sheet.CacheMinutes = v.cfg.Sheet.CacheMinutes
	})
	if err != nil {
		return failure("%v", err)
	}
	v.cfg = updated
	changed, aerr := gpgkeys.EnsureCacheTTL(
		time.Duration(v.cfg.Agent.DefaultCacheTTL)*time.Second,
		time.Duration(v.cfg.Agent.MaxCacheTTL)*time.Second,
	)
	v.dirty = false
	if aerr != nil {
		return failure("saved, but gpg-agent: %v", aerr)
	}
	if changed {
		return tea.Batch(
			status("saved — the agent was reloaded, so everything will ask once more"),
			refreshAgent,
		)
	}
	return status("saved — the lock takes effect next time keyforge starts")
}

func (v *settingsView) Render(w, h int) string {
	var b strings.Builder

	// The state the numbers below are currently producing. A setting shown without what it is
	// doing is half of what the reader needs.
	b.WriteString("  " + stDim.Render("right now: "))
	switch {
	case !passstore.Available():
		b.WriteString(stDim.Render("no store on this machine"))
	case v.cached:
		b.WriteString(stWarn.Render("the agent is holding a passphrase") +
			stDim.Render(fmt.Sprintf(" · up to %s idle, %s in all", short(v.ttl.Default), short(v.ttl.Max))))
	default:
		b.WriteString(stGood.Render("the agent is holding nothing"))
	}
	b.WriteString("\n\n")

	for i, s := range settings {
		mark := "  "
		row := stRow
		if i == v.sel {
			mark = stKey.Render(pointer) + " "
			row = stRowSel
		}
		value := s.get(v)
		if v.editing && i == v.sel {
			b.WriteString(mark + cell(s.label, 30, row) + " " + v.buf.render(true) + "\n")
			continue
		}
		bg := row.GetBackground()
		b.WriteString(mark + cell(s.label, 30, row) + " " + cell(value, 22, stFg.Background(bg)) + "\n")
	}

	if v.sel < len(settings) {
		b.WriteString("\n" + indent(stDim.Render(wrapText(settings[v.sel].note, maxi(w-6, 30))), 2) + "\n")
	}
	if v.dirty {
		b.WriteString("\n  " + stWarn.Render("changed — [w] writes it"))
	}
	return b.String()
}

func (v *settingsView) Footer() string {
	if v.editing {
		return joinHints(hint("enter", "accept"), hint("esc", "cancel"))
	}
	f := []string{hint("j/k", "move"), hint("enter", "change")}
	if v.dirty {
		f = append(f, hint("w", "write"))
	}
	return joinHints(f...)
}

// yesno is the PLAIN word, unstyled.
//
// `onoff` returns a coloured one, and a coloured one cannot go through `cell`: the escape
// codes are counted as letters, so a two-character value is truncated to "ye…" in a column
// twenty-two wide. Style is applied by the caller, after the padding — which is the rule the
// whole table layout here depends on.
func yesno(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func orNone(s string) string {
	if strings.TrimSpace(s) == "" {
		return "none"
	}
	return s
}

func secs(n int, whenZero string) string {
	if n <= 0 {
		return whenZero
	}
	return short(time.Duration(n) * time.Second)
}

func mins(n int) string {
	if n <= 0 {
		return "asks every time"
	}
	return short(time.Duration(n) * time.Minute)
}

// wrapText folds a note to the width, at character boundaries.
func wrapText(s string, width int) string {
	var out []string
	cur := ""
	for _, word := range strings.Fields(s) {
		if cur != "" && len([]rune(cur))+1+len([]rune(word)) > width {
			out = append(out, cur)
			cur = ""
		}
		if cur != "" {
			cur += " "
		}
		cur += word
	}
	if cur != "" {
		out = append(out, cur)
	}
	return strings.Join(out, "\n")
}
