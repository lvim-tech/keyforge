package gpgkeys

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/lvim-tech/keyforge/internal/sys"
)

// Pinentry is what will actually appear when a passphrase is needed.
//
// It belongs in an audit because it is the last link in the chain and the least examined
// one. Everything else here asks whether a secret is protected; this asks whether the
// question can be put to you at all, and whether the program putting it is one you want
// holding the answer. On this machine both went wrong at once and neither made a sound: the
// configured pinentry was X11-only in a Wayland session, so anything launched without a
// terminal got no prompt and a failure with no cause; and every graphical alternative
// installed links libsecret, so each could offer to hand the passphrase to a keyring —
// turning the master password of a password store into something guarded by the login
// password instead of by memory.
type Pinentry struct {
	Path       string // resolved program, "" when none is configured and none is on PATH
	FromConfig bool   // named by pinentry-program rather than found by default
	ConfPath   string

	// X11Only reports a program that cannot open a window without an X server. Fatal in a
	// Wayland session with no XWayland display: it degrades to drawing in whatever terminal
	// is attached, and when there is none it simply fails.
	X11Only bool

	// LinksKeyring reports a program built against libsecret, i.e. one that can offer to
	// store the passphrase in the OS keyring.
	LinksKeyring bool
}

// SessionIsWayland reports a session with no X display, where an X11-only pinentry has
// nowhere to draw.
func SessionIsWayland() bool {
	return os.Getenv("WAYLAND_DISPLAY") != "" && os.Getenv("DISPLAY") == ""
}

// KeyringRunning reports a Secret Service daemon that would accept a stored passphrase. The
// offer only exists when something is listening for it.
func KeyringRunning() bool {
	res, err := sys.Run("pgrep", "-x", "gnome-keyring-daemon")
	if err == nil && res.OK() && strings.TrimSpace(res.Stdout) != "" {
		return true
	}
	res, err = sys.Run("pgrep", "-x", "kwalletd6")
	return err == nil && res.OK() && strings.TrimSpace(res.Stdout) != ""
}

// CurrentPinentry works out which program the agent will run, and what it is made of.
func CurrentPinentry() Pinentry {
	p := Pinentry{ConfPath: agentConfPath()}

	if b, err := os.ReadFile(p.ConfPath); err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "#") {
				continue
			}
			if rest, ok := strings.CutPrefix(line, "pinentry-program"); ok {
				if v := strings.TrimSpace(rest); v != "" {
					p.Path, p.FromConfig = v, true
				}
			}
		}
	}
	if p.Path == "" {
		// No line, so gpg-agent falls back to whatever `pinentry` resolves to.
		p.Path = sys.Which("pinentry")
	}
	if p.Path == "" {
		return p
	}

	// GTK2 has no Wayland backend at all — the toolkit predates it — so a gtk-2 pinentry is
	// X11-only however new the rest of the system is. Read from the name rather than from
	// the linkage because the name is the fact: /usr/bin/pinentry-gtk-2 is that program.
	base := filepath.Base(p.Path)
	p.X11Only = strings.Contains(base, "gtk-2") || strings.Contains(base, "gtk2")

	// A program that does not link libsecret cannot offer to store anything, whatever its
	// dialog says. This is the honest test: not what the manual claims, but what the binary
	// is actually built against.
	if res, err := sys.Run("ldd", p.Path); err == nil && res.OK() {
		p.LinksKeyring = strings.Contains(res.Stdout, "libsecret")
	}
	return p
}
