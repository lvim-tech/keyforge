package ui

import (
	"errors"
	"fmt"
	"github.com/charmbracelet/lipgloss"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/lvim-tech/keyforge/internal/audit"
	"github.com/lvim-tech/keyforge/internal/certs"
	"github.com/lvim-tech/keyforge/internal/gpgkeys"
)

// errNoGPG reports a machine that simply has no gpg. That is a fact about the machine, not a
// failure of the tool, and the view says so plainly instead of showing an empty list.
var errNoGPG = errors.New("gpg is not on this machine")

// ── Audit ─────────────────────────────────────────────────────────────────────

type auditView struct {
	rep    audit.Report
	sel    int
	loaded bool
}

func newAuditView() *auditView { return &auditView{} }

func (v *auditView) Title() string { return "Audit" }
func (v *auditView) Init() tea.Cmd { return loadAudit }

type auditLoaded struct{ rep audit.Report }

func loadAudit() tea.Msg { return auditLoaded{rep: audit.Run()} }

func (v *auditView) Update(msg tea.Msg) (view, tea.Cmd) {
	switch msg := msg.(type) {
	case reloadMsg:
		return v, loadAudit
	case auditLoaded:
		v.rep = msg.rep
		v.loaded = true
		if v.sel >= len(v.rep.Findings) {
			v.sel = 0
		}
	case tea.KeyMsg:
		switch msg.String() {
		case "j", "down":
			if v.sel < len(v.rep.Findings)-1 {
				v.sel++
			}
		case "k", "up":
			if v.sel > 0 {
				v.sel--
			}
		case "r":
			return v, loadAudit
		}
	}
	return v, nil
}

func (v *auditView) Render(w, h int) string {
	if !v.loaded {
		return stDim.Render("  checking…")
	}
	high, warn, info := v.rep.Counts()
	var b strings.Builder

	b.WriteString(fmt.Sprintf("  %s %d   %s %d   %s %d   %s\n\n",
		stBad.Render("high"), high,
		stWarn.Render("warn"), warn,
		stDim.Render("info"), info,
		stDim.Render(fmt.Sprintf("· %d keys · %d known hosts (%d hashed)", v.rep.Keys, v.rep.Hosts, v.rep.Hashed))))

	if len(v.rep.Findings) == 0 {
		b.WriteString(stGood.Render("  Nothing to report.") + "\n")
		return b.String()
	}

	// Show the worst first: a screen that opens on "info" teaches you to scroll past it.
	order := []audit.Severity{audit.High, audit.Warn, audit.Info}
	// Windowed on the FLAT index, the same one the cursor moves along, so the band follows the
	// selection across the three severity passes rather than per pass. The selected row draws a
	// second line for its action, hence the extra row of slack.
	start, end := window(len(v.rep.Findings), v.sel, maxi(h-5, 1))
	if start > 0 {
		b.WriteString(stDim.Render(fmt.Sprintf("     … %d above", start)) + "\n")
	}
	idx := 0
	for _, sev := range order {
		for _, f := range v.rep.Findings {
			if f.Severity != sev {
				continue
			}
			if idx < start || idx >= end {
				idx++
				continue
			}
			mark := "  "
			if idx == v.sel {
				mark = stKey.Render(pointer) + " "
			}
			// The dot is coloured through a style that CARRIES the row background, and the
			// rest goes through cell — never a pre-rendered string inside another Render.
			// lipgloss wraps a rendered line in one sequence, so the inner style's reset ended
			// the selection background after the first glyph and the row was highlighted for
			// exactly one character.
			row := stRow
			if idx == v.sel {
				row = stRowSel
			}
			bg := row.GetBackground()
			// One glyph for all three severities, told apart by COLOUR alone. Info used to be a
			// middle dot — a different, much smaller shape — so the informational rows read as
			// a ragged second-class list rather than as the same list at a lower severity. The
			// severity is the colour's job here; making it the size's job as well says the same
			// thing twice and disagrees with itself at a glance.
			dot := "●"
			dotStyle := stDim.Background(bg)
			switch sev {
			case audit.High:
				dotStyle = stBad.Background(bg)
			case audit.Warn:
				dotStyle = stWarn.Background(bg)
			}
			msgW := maxi(w-32, 8)
			line := dotStyle.Render(dot) + " " +
				cell(trunc(f.Subject, 22), 22, row) + " " +
				cell(f.Message, msgW, row)
			b.WriteString(mark + line + "\n")
			if idx == v.sel {
				// The row is one line so the list stays scannable, and the row under the
				// cursor says all of itself underneath. Truncation is fine for reading down a
				// column; it is not fine for the one finding you stopped on, where the part
				// that got cut is usually the part that tells you what to do.
				if len([]rune(f.Message)) > msgW {
					b.WriteString(indent(stFg.Render(wrapText(f.Message, maxi(w-6, 24))), 5) + "\n")
				}
				// Only when there is one. A finding that reports the state is fine is built
				// with an empty Action on purpose — there is nothing to do about good news —
				// and drawing the arrow regardless left a bare "→" pointing at nothing, which
				// reads as a message that failed to load rather than as an absence of one.
				if f.Action != "" {
					for _, l := range hanging("→ ", f.Action, maxi(w-6, 24)) {
						b.WriteString(indent(stNote.Render(l), 5) + "\n")
					}
				}
			}
			idx++
		}
	}
	if end < len(v.rep.Findings) {
		b.WriteString(stDim.Render(fmt.Sprintf("     … %d below", len(v.rep.Findings)-end)) + "\n")
	}
	return b.String()
}

func (v *auditView) Footer() string {
	return joinHints(hint("j/k", "move"), hint("r", "check again"))
}

// ── GPG ───────────────────────────────────────────────────────────────────────

type gpgView struct {
	keys   []gpgkeys.Key
	sel    int
	loaded bool
	err    string
}

func newGPGView() *gpgView { return &gpgView{} }

func (v *gpgView) Title() string { return "GPG" }
func (v *gpgView) Init() tea.Cmd { return loadGPG }

type gpgLoaded struct {
	keys []gpgkeys.Key
	err  error
}

func loadGPG() tea.Msg {
	if !gpgkeys.Available() {
		return gpgLoaded{err: errNoGPG}
	}
	k, err := gpgkeys.List()
	return gpgLoaded{keys: k, err: err}
}

func (v *gpgView) Update(msg tea.Msg) (view, tea.Cmd) {
	switch msg := msg.(type) {
	case reloadMsg:
		return v, loadGPG
	case gpgLoaded:
		if msg.err != nil {
			v.err = msg.err.Error()
		} else {
			v.keys, v.err = msg.keys, ""
		}
		v.loaded = true
	case tea.KeyMsg:
		switch msg.String() {
		case "j", "down":
			if v.sel < len(v.keys)-1 {
				v.sel++
			}
		case "k", "up":
			if v.sel > 0 {
				v.sel--
			}
		case "r":
			return v, loadGPG
		}
	}
	return v, nil
}

func (v *gpgView) Render(w, h int) string {
	if !v.loaded {
		return stDim.Render("  reading the keyring…")
	}
	if v.err != "" {
		return stErr.Render("  " + v.err)
	}
	if len(v.keys) == 0 {
		return stDim.Render("  no secret GPG keys")
	}
	var b strings.Builder
	b.WriteString(stDim.Render(fmt.Sprintf("  %-18s %-12s %-12s %s", "key", "type", "expires", "identity")) + "\n")
	gstart, gend := window(len(v.keys), v.sel, maxi(h-3, 1))
	if gstart > 0 {
		b.WriteString(stDim.Render(fmt.Sprintf("     … %d above", gstart)) + "\n")
	}
	for i, k := range v.keys[gstart:gend] {
		i += gstart
		mark := "  "
		row := stRow
		if i == v.sel {
			mark = stKey.Render(pointer) + " "
			row = stRowSel
		}
		expText, expStyle := "never", stDim
		switch {
		case k.Expired():
			expText, expStyle = "expired", stBad
		case k.ExpiringSoon(60 * 24 * time.Hour):
			expText, expStyle = k.Expires.Format("2006-01-02"), stWarn
		case !k.Expires.IsZero():
			expText, expStyle = k.Expires.Format("2006-01-02"), stFg
		}
		// Named when it is the subkey's, because "expired" against a primary key that is fine
		// sends the reader to renew the wrong thing.
		if k.ExpiryIsSubkey && expText != "never" {
			expText += " (sub)"
		}
		uid := ""
		if len(k.UIDs) > 0 {
			uid = k.UIDs[0]
		}
		id := k.ID
		if len(id) > 16 {
			id = id[len(id)-16:]
		}
		bg := row.GetBackground()
		b.WriteString(mark +
			cell(id, 18, row) + " " +
			cell(k.Type, 12, stFg.Background(bg)) + " " +
			cell(expText, 12, expStyle.Background(bg)) + " " +
			cell(uid, maxi(w-48, 10), row) + "\n")
	}
	if gend < len(v.keys) {
		b.WriteString(stDim.Render(fmt.Sprintf("     … %d below", len(v.keys)-gend)) + "\n")
	}
	// Every identity on the selected key, whole. The column holds one and cuts it; a key with
	// three uids is a key whose column says nothing useful about which one it is.
	if v.sel < len(v.keys) {
		k := v.keys[v.sel]
		b.WriteString("\n")
		for _, uid := range k.UIDs {
			for _, l := range hanging("· ", uid, maxi(w-6, 24)) {
				b.WriteString(indent(stDim.Render(l), 2) + "\n")
			}
		}
		if !k.SubkeyExpires.IsZero() {
			b.WriteString(indent(stDim.Render("encryption subkey expires "+
				k.SubkeyExpires.Format("2006-01-02")), 2) + "\n")
		}
	}
	b.WriteString("\n" + stDim.Render("  An expiring GPG key stops `pass` and signed commits without warning.\n"+
		"  Extend it without replacing the key:  gpg --quick-set-expire <fpr> 2y"))
	return b.String()
}

func (v *gpgView) Footer() string {
	return joinHints(hint("j/k", "move"), hint("r", "reload"))
}

// ── Certificates ──────────────────────────────────────────────────────────────

type certView struct {
	list   []certs.Cert
	roots  []string
	sel    int
	loaded bool
}

// newCertView takes the roots from the config, falling back to the built-in list.
//
// `cert_paths` was declared in the Config type and read by nothing: the scan always used
// DefaultPaths, so a machine that keeps its certificates somewhere else could name the
// directory in the config and watch keyforge ignore it. A field that is written and never
// read describes a setting that does not exist.
func newCertView(roots []string) *certView {
	if len(roots) == 0 {
		roots = certs.DefaultPaths()
	}
	return &certView{roots: roots}
}

func (v *certView) Title() string { return "Certs" }
func (v *certView) Init() tea.Cmd { return v.load() }

type certsLoaded struct{ list []certs.Cert }

func (v *certView) load() tea.Cmd {
	roots := v.roots
	return func() tea.Msg { return certsLoaded{list: certs.Scan(roots, 2)} }
}

func (v *certView) Update(msg tea.Msg) (view, tea.Cmd) {
	switch msg := msg.(type) {
	case reloadMsg:
		return v, v.load()
	case certsLoaded:
		v.list = msg.list
		v.loaded = true
		if v.sel >= len(v.list) {
			v.sel = 0
		}
	case tea.KeyMsg:
		switch msg.String() {
		case "j", "down":
			if v.sel < len(v.list)-1 {
				v.sel++
			}
		case "k", "up":
			if v.sel > 0 {
				v.sel--
			}
		case "r":
			return v, v.load()
		}
	}
	return v, nil
}

func (v *certView) Render(w, h int) string {
	if !v.loaded {
		return stDim.Render("  looking for certificates…")
	}
	if len(v.list) == 0 {
		return stDim.Render("  no certificates found in " + strings.Join(v.roots, ", "))
	}
	var b strings.Builder
	b.WriteString(stDim.Render(fmt.Sprintf("  %-32s %-24s %s", "subject", "validity", "file")) + "\n")
	cstart, cend := window(len(v.list), v.sel, maxi(h-3, 1))
	if cstart > 0 {
		b.WriteString(stDim.Render(fmt.Sprintf("     … %d above", cstart)) + "\n")
	}
	for i, c := range v.list[cstart:cend] {
		i += cstart
		mark := "  "
		row := stRow
		if i == v.sel {
			mark = stKey.Render(pointer) + " "
			row = stRowSel
		}
		st := stFg
		if c.Expired() {
			st = stBad
		} else if c.Days() < 30 {
			st = stWarn
		}
		subject := c.Subject
		if c.IsCA {
			subject += " [CA]"
		}
		bg := row.GetBackground()
		b.WriteString(mark +
			cell(subject, 32, row) + " " +
			cell(c.Summary(), 24, st.Background(bg)) + " " +
			cell(c.Path, maxi(w-62, 12), stDim.Background(bg)) + "\n")
	}
	// The detail of the selected certificate, folded rather than run off the edge. Issuer
	// strings and SAN lists are routinely longer than a terminal, and the path — the answer to
	// "which of these two identically named certificates is it" — is the first thing the column
	// cuts.
	if v.sel < len(v.list) {
		c := v.list[v.sel]
		room := maxi(w-13, 24)
		field := func(label, value string, st lipgloss.Style) {
			if value == "" {
				return
			}
			for i, l := range strings.Split(wrapText(value, room), "\n") {
				if i == 0 {
					b.WriteString("\n" + stDim.Render(fmt.Sprintf("  %-9s", label)) + st.Render(l))
					continue
				}
				b.WriteString("\n" + strings.Repeat(" ", 11) + st.Render(l))
			}
		}
		b.WriteString("\n")
		field("file:", c.Path, stFg)
		issuer := c.Issuer
		if c.SelfSign {
			issuer += "  (self-signed)"
		}
		field("issuer:", issuer, stFg)
		field("names:", strings.Join(c.DNS, ", "), stFg)
		b.WriteString("\n")
	}
	return b.String()
}

func (v *certView) Footer() string {
	return joinHints(hint("j/k", "move"), hint("r", "rescan"))
}
