package gpgkeys

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/lvim-tech/keyforge/internal/sys"
)

// Protection is what gpg-agent knows about one secret key's passphrase.
//
// This is the GPG counterpart of the `ssh-keygen -y -P ""` trick, and it matters for the same
// reason: there is no honest way to tell from the key FILE whether it is protected. The private
// keys under ~/.gnupg/private-keys-v1.d are S-expressions whose protection lives inside the
// structure, and guessing at it by pattern is exactly the sort of thing that reports "encrypted"
// for a key that is not. The agent already knows, and it will say so.
type Protection struct {
	Keygrip   string
	Known     bool // the agent answered at all
	Protected bool // the private key is encrypted with a passphrase
	Cached    bool // the agent is holding that passphrase RIGHT NOW
	TTL       time.Duration
}

// Protections asks gpg-agent about every secret key it holds, keyed by keygrip.
//
// The reply format is fixed:
//
//	S KEYINFO <keygrip> <type> <serialno> <idstr> <cached> <protection> <fpr> <ttl> <flags> …
//	  0    1       2       3        4        5       6          7         8     9      10
//
// where protection is P (passphrase), C (clear — none at all) or - (it would not say), and cached
// is 1 while the agent still remembers the passphrase. That last column is the one the README's
// "root on the machine while the agent remembers" row is really about, so it is worth reporting.
func Protections() map[string]Protection {
	if !sys.Have("gpg-connect-agent") {
		return nil
	}
	res, err := sys.Run("gpg-connect-agent", "KEYINFO --list", "/bye")
	if err != nil || !res.OK() {
		return nil
	}
	return parseKeyInfo(res.Stdout)
}

func parseKeyInfo(out string) map[string]Protection {
	res := map[string]Protection{}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 8 || f[0] != "S" || f[1] != "KEYINFO" {
			continue
		}
		p := Protection{Keygrip: f[2], Known: true}
		p.Cached = f[6] == "1"
		switch f[7] {
		case "P":
			p.Protected = true
		case "C":
			p.Protected = false
		default:
			p.Known = false
		}
		if len(f) > 9 {
			if n, err := strconv.Atoi(f[9]); err == nil && n > 0 {
				p.TTL = time.Duration(n) * time.Second
			}
		}
		res[p.Keygrip] = p
	}
	return res
}

// EncryptionKeygrip returns the keygrip of the subkey that actually decrypts for the given
// recipient, plus the key id it belongs to.
//
// The distinction is not pedantry: a `pass` entry is encrypted to the ENCRYPTION subkey, so that is
// the key whose passphrase stands between a stolen store and its contents. Checking the primary key
// instead would report on a key that is never asked for when you open an entry — and on many
// keyrings the primary is offline while the subkey is not, which would turn the answer upside down.
//
// Case in the capability field is what separates the two, and it is easy to get wrong: on a `sec`
// line, LOWERCASE letters are what that key itself can do, while UPPERCASE ones are the sum over
// the whole keyblock. A primary that only signs and certifies still reads "scESC", so matching
// case-insensitively picks the primary every time and never looks at the subkey that actually
// decrypts.
func EncryptionKeygrip(recipient string) (grip, keyID string) {
	if recipient == "" || !Available() {
		return "", ""
	}
	res, err := sys.Run("gpg", "--list-secret-keys", "--with-colons", "--fixed-list-mode",
		"--with-keygrip", recipient)
	if err != nil || !res.OK() {
		return "", ""
	}
	return parseEncryptionKeygrip(res.Stdout)
}

func parseEncryptionKeygrip(out string) (grip, keyID string) {
	// Walk the records in order: each grp line belongs to the key record above it.
	var curID, curCaps, primaryID string
	var fallbackGrip, fallbackID string
	for _, line := range strings.Split(out, "\n") {
		f := strings.Split(line, ":")
		if len(f) < 2 {
			continue
		}
		switch f[0] {
		case "sec", "ssb":
			curID, curCaps = fieldAt(f, 4), fieldAt(f, 11)
			if f[0] == "sec" {
				primaryID = curID
			}
		case "grp":
			g := fieldAt(f, 9)
			if g == "" {
				continue
			}
			if strings.Contains(curCaps, "e") {
				id := curID
				if id == "" {
					id = primaryID
				}
				return g, id
			}
			if fallbackGrip == "" {
				fallbackGrip, fallbackID = g, curID
			}
		}
	}
	return fallbackGrip, fallbackID
}

// StoreProtection answers the question the whole password store rests on: is there a passphrase
// between a copy of ~/.password-store and everything in it.
//
// Known=false is a real answer and is reported as such rather than smoothed into "protected" —
// claiming a protection that was never verified is the one failure mode this program refuses.
//
// The key id comes back with it because the answer is only actionable together with the key it is
// about: changing the store's master password means running gpg against exactly that key.
func StoreProtection(recipient string) (Protection, string) {
	grip, id := EncryptionKeygrip(recipient)
	if grip == "" {
		return Protection{}, ""
	}
	p := Protections()[grip]
	p.Keygrip = grip
	return p, id
}

// ChangePassphraseCmd changes the passphrase of a GPG key — the store's master password, when the
// key is the one `pass` encrypts to.
//
// Interactive, and it has to be: gpg asks through pinentry, and the new passphrase is typed into
// gpg itself. There is no flag that takes it on the command line here for the same reason keyforge
// never passes one to ssh-keygen.
func ChangePassphraseCmd(keyID string) *exec.Cmd {
	return sys.Interactive("gpg", "--change-passphrase", keyID)
}

// CacheTTL is how long gpg-agent will keep a passphrase after it is entered.
//
// It decides the width of the window in which a machine that is already compromised can read the
// store without knowing anything. The defaults are gpg's own; they are stated here because an agent
// with no config file is the common case, and reporting "not configured" without saying what that
// means in seconds would be reporting nothing.
type CacheTTL struct {
	Default    time.Duration
	Max        time.Duration
	Configured bool // a value was actually set in gpg-agent.conf
	Path       string
}

// AgentCacheTTL reads gpg-agent.conf, falling back to gpg's documented defaults.
func AgentCacheTTL() CacheTTL {
	t := CacheTTL{Default: 600 * time.Second, Max: 7200 * time.Second}
	home := os.Getenv("GNUPGHOME")
	if home == "" {
		h, err := os.UserHomeDir()
		if err != nil {
			return t
		}
		home = filepath.Join(h, ".gnupg")
	}
	t.Path = filepath.Join(home, "gpg-agent.conf")
	b, err := os.ReadFile(t.Path)
	if err != nil {
		return t
	}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, val, ok := strings.Cut(line, " ")
		if !ok {
			continue
		}
		n, err := strconv.Atoi(strings.TrimSpace(val))
		if err != nil {
			continue
		}
		switch key {
		case "default-cache-ttl":
			t.Default, t.Configured = time.Duration(n)*time.Second, true
		case "max-cache-ttl":
			t.Max, t.Configured = time.Duration(n)*time.Second, true
		}
	}
	return t
}
