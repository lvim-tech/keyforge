// Package gpgkeys reads the local GPG keyring.
//
// Only the secret keys are listed, and deliberately so: a public key you hold is someone else's
// business, while a secret key is something you are responsible for — its expiry, its passphrase,
// and the fact that `pass` and every signed commit depend on it still working.
package gpgkeys

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/lvim-tech/keyforge/internal/sys"
)

// Key is one secret key in the keyring.
type Key struct {
	ID      string
	Type    string // rsa4096, ed25519 …
	Created time.Time
	// Expires is the date that matters — the SOONEST of the primary key and the encryption
	// subkey, not the primary's alone. The store stops working on whichever comes first.
	Expires time.Time // zero when it never expires
	// SubkeyExpires is the encryption subkey's own date, zero when there is none.
	SubkeyExpires time.Time
	// ExpiryIsSubkey says the date above came from the subkey, so the interface can name it.
	ExpiryIsSubkey bool
	UIDs           []string
	Usage          string // S=sign C=certify E=encrypt A=authenticate
}

// Expired reports whether the key is past its expiry.
func (k Key) Expired() bool { return !k.Expires.IsZero() && time.Now().After(k.Expires) }

// ExpiringSoon reports whether the key runs out within the given window — the case that actually
// hurts, because it fails silently at the worst moment rather than announcing itself.
func (k Key) ExpiringSoon(d time.Duration) bool {
	return !k.Expires.IsZero() && !k.Expired() && time.Until(k.Expires) < d
}

// Available reports whether gpg is on this machine.
func Available() bool { return sys.Have("gpg") }

// List returns the secret keys. Parsing uses --with-colons, gpg's machine-readable format, which is
// the only output it promises not to change between versions.
func List() ([]Key, error) {
	res, err := sys.Run("gpg", "--list-secret-keys", "--with-colons", "--fixed-list-mode")
	if err != nil {
		return nil, err
	}
	// A non-zero exit returned (nil, nil), so a broken keyring rendered as "no secret GPG keys".
	// An empty answer and a failed question are different facts, and this tab exists to report
	// the state of the keyring rather than to summarise it away.
	if !res.OK() {
		msg := strings.TrimSpace(res.Stderr)
		if i := strings.IndexByte(msg, '\n'); i >= 0 {
			msg = msg[:i]
		}
		if msg == "" {
			msg = fmt.Sprintf("gpg exited %d", res.Code)
		}
		return nil, errors.New(msg)
	}
	return parseKeys(res.Stdout), nil
}

// parseKeys reads gpg's --with-colons output. Split from List so it can be tested against a
// canned keyring — the same shape agent.go's parseKeyInfo has, and for the same reason: the
// interesting cases here are keyrings this machine does not happen to have.
func parseKeys(stdout string) []Key {
	var out []Key
	var cur *Key
	for _, line := range strings.Split(stdout, "\n") {
		f := strings.Split(line, ":")
		if len(f) < 2 {
			continue
		}
		switch f[0] {
		case "sec":
			if cur != nil {
				out = append(out, *cur)
			}
			cur = &Key{}
			if len(f) > 4 {
				cur.ID = f[4]
			}
			if len(f) > 16 && f[16] != "" {
				cur.Type = f[16]
			} else if len(f) > 3 {
				cur.Type = algoName(f[3]) + f[2]
			}
			cur.Created = epoch(fieldAt(f, 5))
			cur.Expires = epoch(fieldAt(f, 6))
			cur.Usage = fieldAt(f, 11)
		case "ssb":
			// THE SUBKEY IS THE ONE THAT STOPS `pass`. This tab exists to warn about an expiry
			// that silently breaks the store, and only the primary key's date was read — on the
			// ordinary keyring shape (primary certifies, subkey encrypts) those are different
			// dates, and the one on screen was the wrong one. A user could read "expires 2030"
			// while the subkey that actually decrypts died last month.
			if cur == nil {
				break
			}
			if !strings.ContainsRune(fieldAt(f, 11), 'e') {
				break
			}
			exp := epoch(fieldAt(f, 6))
			cur.SubkeyExpires = exp
			// The soonest of the two is what the columns show, because it is the one that bites.
			if !exp.IsZero() && (cur.Expires.IsZero() || exp.Before(cur.Expires)) {
				cur.Expires = exp
				cur.ExpiryIsSubkey = true
			}
		case "uid":
			if cur != nil {
				if u := fieldAt(f, 9); u != "" {
					cur.UIDs = append(cur.UIDs, u)
				}
			}
		}
	}
	if cur != nil {
		out = append(out, *cur)
	}
	return out
}

func fieldAt(f []string, i int) string {
	if i < len(f) {
		return f[i]
	}
	return ""
}

func epoch(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n == 0 {
		return time.Time{}
	}
	return time.Unix(n, 0)
}

func algoName(id string) string {
	switch id {
	case "1":
		return "rsa"
	case "17":
		return "dsa"
	case "18":
		return "ecdh"
	case "19":
		return "ecdsa"
	case "22":
		return "eddsa"
	}
	return "algo" + id
}
