// Package gpgkeys reads the local GPG keyring.
//
// Only the secret keys are listed, and deliberately so: a public key you hold is someone else's
// business, while a secret key is something you are responsible for — its expiry, its passphrase,
// and the fact that `pass` and every signed commit depend on it still working.
package gpgkeys

import (
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
	Expires time.Time // zero when it never expires
	UIDs    []string
	Usage   string // S=sign C=certify E=encrypt A=authenticate
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
	if err != nil || !res.OK() {
		return nil, err
	}
	var out []Key
	var cur *Key
	for _, line := range strings.Split(res.Stdout, "\n") {
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
	return out, nil
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
