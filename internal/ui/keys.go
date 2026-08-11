package ui

import (
	"fmt"
	"sort"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/lvim-tech/keyforge/internal/config"
	"github.com/lvim-tech/keyforge/internal/passstore"
	"github.com/lvim-tech/keyforge/internal/sshkeys"
	"github.com/lvim-tech/keyforge/internal/sys"
)

type keysMode int

const (
	kmList keysMode = iota
	kmNew           // filling in the form for a new key
	kmHost          // asking for a target host
	kmDetail
)

// hostPurpose says what the host being typed is for.
type hostPurpose int

const (
	hpDeploy hostPurpose = iota
	hpRevoke
	hpList
)

type keysView struct {
	// rounds is the configured bcrypt-KDF cost for new keys and passphrase changes.
	rounds int

	keys   []sshkeys.Key
	sel    int
	mode   keysMode
	err    string
	detail string

	// new-key form
	fName, fComment input
	fType           string
	fField          int

	// host prompt
	fHost   input
	purpose hostPurpose
}

// newKeysView takes the config for kdf_rounds, which until now was written by the config and
// read by nobody: both the new-key path and the change-passphrase path used a literal 100, so a
// user asking for stronger KDF rounds silently got the default. Same defect class as the four
// dead fields found before it.
func newKeysView(c config.Config) *keysView {
	v := &keysView{
		rounds:   c.KDFRounds,
		fName:    newInput("file", "e.g. github-2026"),
		fComment: newInput("comment", "user@machine"),
		fHost:    newInput("host", "user@machine or an alias from ~/.ssh/config"),
		fType:    "ed25519",
	}
	return v
}

func (v *keysView) Title() string { return "Keys" }

func (v *keysView) capturesInput() bool { return v.mode == kmNew || v.mode == kmHost }

func (v *keysView) Init() tea.Cmd { return loadKeys }

// keysLoaded carries the result of a scan back to the UI thread.
type keysLoaded struct {
	keys []sshkeys.Key
	err  error
}

// loadKeys runs the scan as a command. It is not cheap — describing eight keys means two dozen
// ssh-keygen invocations — and doing it inline would freeze the interface on every reload, which
// is exactly what happened before this was split out.
func loadKeys() tea.Msg {
	keys, err := sshkeys.Scan()
	return keysLoaded{keys: keys, err: err}
}

func (v *keysView) current() (sshkeys.Key, bool) {
	if v.sel < 0 || v.sel >= len(v.keys) {
		return sshkeys.Key{}, false
	}
	return v.keys[v.sel], true
}

func (v *keysView) Update(msg tea.Msg) (view, tea.Cmd) {
	switch msg := msg.(type) {
	case reloadMsg:
		return v, loadKeys

	case keysLoaded:
		if msg.err != nil {
			v.err = msg.err.Error()
			return v, nil
		}
		v.err, v.keys = "", msg.keys
		if v.sel >= len(v.keys) {
			v.sel = max(0, len(v.keys)-1)
		}
		return v, nil

	case tea.KeyMsg:
		switch v.mode {
		case kmNew:
			return v.updateNew(msg)
		case kmHost:
			return v.updateHost(msg)
		case kmDetail:
			if msg.String() == "esc" || msg.String() == "enter" || msg.String() == "q" {
				v.mode = kmList
			}
			return v, nil
		}
		return v.updateList(msg)
	}
	return v, nil
}

func (v *keysView) updateList(msg tea.KeyMsg) (view, tea.Cmd) {
	switch msg.String() {
	case "j", "down":
		if v.sel < len(v.keys)-1 {
			v.sel++
		}
	case "k", "up":
		if v.sel > 0 {
			v.sel--
		}
	case "g":
		v.sel = 0
	case "G":
		v.sel = max(0, len(v.keys)-1)

	case "n":
		v.mode = kmNew
		v.fField = 0
		spec := sshkeys.DefaultSpec()
		v.fName.set("")
		v.fComment.set(spec.Comment)
		v.fType = "ed25519"

	case "p":
		if k, ok := v.current(); ok {
			return v, func() tea.Msg {
				return execMsg{
					cmd:  sshkeys.ChangePassphraseCmd(k, v.rounds),
					then: k.Name + " has a new passphrase (the key was rewritten in OpenSSH format)",
				}
			}
		}

	case "c":
		if k, ok := v.current(); ok {
			pub, err := sshkeys.PublicKey(k)
			if err != nil {
				return v, failure("%v", err)
			}
			if err := sys.Clipboard(pub); err != nil {
				return v, failure("clipboard: %v", err)
			}
			return v, status("the public key of %s is on the clipboard", k.Name)
		}

	case "enter", "f":
		if k, ok := v.current(); ok {
			v.detail = v.buildDetail(k)
			v.mode = kmDetail
		}

	case "d":
		if _, ok := v.current(); ok {
			v.mode, v.purpose = kmHost, hpDeploy
			v.fHost.set("")
		}
	case "r":
		if _, ok := v.current(); ok {
			v.mode, v.purpose = kmHost, hpRevoke
			v.fHost.set("")
		}
	case "a":
		v.mode, v.purpose = kmHost, hpList
		v.fHost.set("")
	}
	return v, nil
}

func (v *keysView) updateNew(msg tea.KeyMsg) (view, tea.Cmd) {
	switch msg.String() {
	case "esc":
		v.mode = kmList
		return v, nil
	case "tab", "down":
		v.fField = (v.fField + 1) % 3
		return v, nil
	case "shift+tab", "up":
		v.fField = (v.fField + 2) % 3
		return v, nil
	case "enter":
		if v.fName.empty() {
			return v, failure("the file name is required")
		}
		spec := sshkeys.DefaultSpec()
		if v.rounds > 0 {
			spec.Rounds = v.rounds
		}
		spec.Name = strings.TrimSpace(v.fName.String())
		spec.Comment = strings.TrimSpace(v.fComment.String())
		spec.Type = v.fType
		if spec.Type == "rsa" {
			spec.Bits = 4096
		}
		if spec.Exists() {
			return v, failure("%s already exists — pick another name", spec.Path())
		}
		v.mode = kmList
		return v, func() tea.Msg {
			return execMsg{
				cmd:  sshkeys.GenerateCmd(spec),
				then: "ready: " + spec.Path() + " — now deploy it with [d] and store the passphrase in pass",
			}
		}
	}
	// Field 2 is the type toggle, not a text field.
	if v.fField == 2 {
		switch msg.String() {
		case "left", "right", "h", "l", " ":
			if v.fType == "ed25519" {
				v.fType = "rsa"
			} else {
				v.fType = "ed25519"
			}
		}
		return v, nil
	}
	if v.fField == 0 {
		v.fName.update(msg)
	} else {
		v.fComment.update(msg)
	}
	return v, nil
}

func (v *keysView) updateHost(msg tea.KeyMsg) (view, tea.Cmd) {
	switch msg.String() {
	case "esc":
		v.mode = kmList
		return v, nil
	case "enter":
		target := strings.TrimSpace(v.fHost.String())
		if target == "" {
			return v, failure("a host is required")
		}
		v.mode = kmList
		k, ok := v.current()
		switch v.purpose {
		case hpDeploy:
			if !ok {
				return v, failure("no key selected")
			}
			cmd, err := sshkeys.DeployCmd(k, target)
			if err != nil {
				return v, failure("%v", err)
			}
			return v, func() tea.Msg {
				return execMsg{cmd: cmd, then: k.Name + " installed on " + target}
			}
		case hpRevoke:
			if !ok {
				return v, failure("no key selected")
			}
			pub, err := sshkeys.PublicKey(k)
			if err != nil {
				return v, failure("%v", err)
			}
			cmd, err := sshkeys.RevokeCmd(pub, target)
			if err != nil {
				return v, failure("%v", err)
			}
			return v, func() tea.Msg {
				return execMsg{cmd: cmd, then: "checked/removed on " + target}
			}
		default:
			return v, func() tea.Msg {
				return execMsg{cmd: sshkeys.AuthorizedKeysCmd(target), then: "read from " + target}
			}
		}
	}
	v.fHost.update(msg)
	return v, nil
}

func (v *keysView) buildDetail(k sshkeys.Key) string {
	sha, md5 := sshkeys.Fingerprints(k)
	var b strings.Builder
	row := func(label, val string) {
		if val != "" {
			fmt.Fprintf(&b, "  %s %s\n", stDim.Render(fmt.Sprintf("%-14s", label)), val)
		}
	}
	row("file", k.Path)
	row("type", fmt.Sprintf("%s %d bits", k.Type, k.Bits))
	row("format", map[string]string{"openssh": "OpenSSH (bcrypt-KDF)", "pem": "PEM (weak passphrase protection)"}[k.Format])
	if k.Encrypted {
		row("passphrase", stGood.Render("yes"))
	} else {
		row("passphrase", stBad.Render("NONE — a copy of the file works immediately"))
	}
	row("comment", k.Comment)
	row("SHA256", sha)
	row("MD5", md5)
	row("mode", fmt.Sprintf("%04o", k.Mode))
	row("modified", k.Modified.Format("2006-01-02 15:04")+stDim.Render(fmt.Sprintf("  (%d days ago)", int(k.Age().Hours()/24))))
	if len(k.Hosts) > 0 {
		row("opens", strings.Join(k.Hosts, ", "))
	}
	if k.InAgent {
		row("in agent", stWarn.Render("yes — right now the passphrase is not protecting it"))
	}
	if pub, err := sshkeys.PublicKey(k); err == nil {
		b.WriteString("\n")
		b.WriteString(stDim.Render("  public key:") + "\n")
		b.WriteString(stFg.Render("  " + wrap(pub, 76)))
		b.WriteString("\n")
	}
	return b.String()
}

func (v *keysView) Render(w, h int) string {
	switch v.mode {
	case kmNew:
		return v.renderNew(w)
	case kmHost:
		return v.renderHost(w)
	case kmDetail:
		return stBox.Width(w - 2).Render(v.detail)
	}
	return v.renderList(w, h)
}

func (v *keysView) renderList(w, h int) string {
	if v.err != "" {
		return stErr.Render(v.err)
	}
	if len(v.keys) == 0 {
		return stDim.Render("  no private keys in " + sshkeys.Dir() + " — press [n] for a new one")
	}
	var b strings.Builder
	head := fmt.Sprintf("  %-20s %-12s %-10s %-8s %s", "key", "type", "passphrase", "format", "opens")
	b.WriteString(stDim.Render(head) + "\n")

	// The rows are windowed to what the terminal can actually show. The shell cuts the body to
	// the height it budgeted — otherwise the footer is pushed off the bottom — so a list longer
	// than the screen would lose its tail silently, cursor and all.
	start, end := window(len(v.keys), v.sel, maxi(h-4, 1))
	if start > 0 {
		b.WriteString(stDim.Render(fmt.Sprintf("     … %d above", start)) + "\n")
	}
	for i, k := range v.keys[start:end] {
		i += start
		mark := "  "
		row := stRow
		if i == v.sel {
			mark = stKey.Render(pointer) + " "
			row = stRowSel
		}
		// Type is unknown when the key is encrypted AND has no .pub beside it: ssh-keygen would
		// need the passphrase to read the private half, and keyforge does not ask for one behind
		// the user's back just to fill in a table cell.
		typText, typStyle := "—", stDim
		if k.Type != "" {
			typText = strings.ToLower(k.Type)
			if k.Bits > 0 {
				typText = fmt.Sprintf("%s/%d", typText, k.Bits)
			}
			typStyle = stFg
			if weak, _ := k.Weak(); weak {
				typStyle = stWarn
			}
		}
		passText, passStyle := "NONE", stBad
		if k.Encrypted {
			passText, passStyle = "yes", stGood
		}
		formatStyle := stFg
		if k.Format == "pem" {
			formatStyle = stWarn
		}
		hosts := strings.Join(k.Hosts, ",")
		hostStyle := stFg
		if hosts == "" {
			hosts, hostStyle = "—", stDim
		}
		if k.InAgent {
			hosts += " "
			hostStyle = stWarn
		}
		line := cell(k.Name, 20, row) + " " +
			cell(typText, 12, typStyle.Background(row.GetBackground())) + " " +
			cell(passText, 8, passStyle.Background(row.GetBackground())) + " " +
			cell(k.Format, 8, formatStyle.Background(row.GetBackground())) + " " +
			cell(hosts, maxi(w-56, 10), hostStyle.Background(row.GetBackground()))
		b.WriteString(mark + line + "\n")
	}
	if end < len(v.keys) {
		b.WriteString(stDim.Render(fmt.Sprintf("     … %d below", len(v.keys)-end)) + "\n")
	}

	if k, ok := v.current(); ok {
		b.WriteString("\n")
		sha, _ := sshkeys.Fingerprints(k)
		b.WriteString(stDim.Render("  " + sha))
		if k.Comment != "" {
			b.WriteString(stDim.Render("  ·  " + k.Comment))
		}
		b.WriteString("\n")
	}
	return b.String()
}

func (v *keysView) renderNew(w int) string {
	var b strings.Builder
	b.WriteString(stAccent.Render("  New SSH key") + "\n\n")
	b.WriteString("  " + v.fName.render(v.fField == 0) + "\n")
	b.WriteString("  " + v.fComment.render(v.fField == 1) + "\n")
	label := stDim.Render("type: ")
	if v.fField == 2 {
		label = stKey.Render("type: ")
	}
	t := v.fType
	if v.fField == 2 {
		t = stRowSel.Render(" " + t + " ")
	}
	b.WriteString("  " + label + t + stDim.Render("   (←/→ switches; ed25519 is the recommended one)") + "\n\n")
	b.WriteString(stDim.Render("  ssh-keygen itself will ask for the passphrase — it does not pass\n"+
		"  through keyforge, nor through the command line. Make one first in the\n"+
		"  Generator tab.") + "\n")
	return stBox.Width(w - 2).Render(b.String())
}

func (v *keysView) renderHost(w int) string {
	var title, note string
	switch v.purpose {
	case hpDeploy:
		title = "Install the public key on a server"
		note = "Runs ssh-copy-id. It will ask for access to the server the usual way."
	case hpRevoke:
		title = "Remove this public key from a server"
		note = "Removes the line from authorized_keys and leaves a backup there.\nThis is the half of a rotation that usually gets skipped."
	default:
		title = "Show a server's authorized_keys"
		note = "Lists which keys can log in there, with fingerprints."
	}
	hosts := sshkeys.ConfigHosts()
	var names []string
	for h := range hosts {
		names = append(names, h)
	}
	sort.Strings(names)

	var b strings.Builder
	b.WriteString(stAccent.Render("  "+title) + "\n\n")
	b.WriteString("  " + v.fHost.render(true) + "\n\n")
	if len(names) > 0 {
		b.WriteString(stDim.Render("  from ~/.ssh/config: ") + stFg.Render(strings.Join(names, "  ")) + "\n\n")
	}
	b.WriteString(stDim.Render("  " + strings.ReplaceAll(note, "\n", "\n  ")))
	return stBox.Width(w - 2).Render(b.String())
}

// shortID trims a recipient to a glance without assuming it is long enough to trim.
func shortID(id string) string {
	r := []rune(id)
	if len(r) <= 8 {
		return id
	}
	return string(r[:8])
}

func (v *keysView) Footer() string {
	switch v.mode {
	case kmNew, kmHost:
		return joinHints(hint("enter", "confirm"), hint("esc", "cancel"))
	case kmDetail:
		return joinHints(hint("esc", "back"))
	}
	f := joinHints(
		hint("n", "new"), hint("p", "passphrase"), hint("c", "copy"),
		hint("d", "deploy"), hint("r", "revoke"), hint("a", "remote"),
		hint("enter", "details"),
	)
	if passstore.Available() {
		// Clamped, not sliced. `[:8]` panicked the whole TUI on the first render of this tab
		// whenever .gpg-id held a short uid — "bob" is a legal recipient, and an empty file
		// passes Available(), which only stats it.
		f += "  " + stDim.Render("· pass: "+shortID(passstore.Recipient()))
	}
	return f
}

// helpers -------------------------------------------------------------------

func trunc(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	if n <= 1 {
		return string(r[:n])
	}
	return string(r[:n-1]) + "…"
}

func padTo(s string, n int) string {
	// Styled substrings carry escape codes, so len() is not the display width; this is only used
	// for the selected row's background and being a little short is harmless.
	if n <= 0 {
		return s
	}
	visible := lipgloss.Width(s)
	if visible >= n {
		return s
	}
	return s + strings.Repeat(" ", n-visible)
}

func wrap(s string, n int) string {
	var out []string
	for len(s) > n {
		out = append(out, s[:n])
		s = s[n:]
	}
	out = append(out, s)
	return strings.Join(out, "\n  ")
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
