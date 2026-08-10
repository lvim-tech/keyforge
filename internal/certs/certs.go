// Package certs inspects X.509 certificates lying around the filesystem.
//
// It exists because of a specific, common failure: a certificate expires, nothing announces it, and
// the first sign is a service that stopped working — or worse, one that kept working because
// something was configured to ignore verification. Reading the dates is a two-second job that
// nobody does, so the tool does it.
//
// Parsing is done with Go's own crypto/x509 rather than by shelling out to openssl. That is not an
// inconsistency with the rest of keyforge: openssl is needed to CREATE keys and certificates, but
// merely reading a public certificate involves no secret, no prompt and no risk — and the parsed
// structure is far more useful than scraping openssl's human-readable output.
package certs

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Cert is one certificate found on disk.
type Cert struct {
	Path     string
	Subject  string
	Issuer   string
	NotAfter time.Time
	IsCA     bool
	SelfSign bool
	DNS      []string
}

// Expired reports whether it is already past its validity.
func (c Cert) Expired() bool { return time.Now().After(c.NotAfter) }

// Days returns the days left, negative when expired.
func (c Cert) Days() int { return int(time.Until(c.NotAfter).Hours() / 24) }

// DefaultPaths are the places worth looking on a workstation that also serves things.
func DefaultPaths() []string {
	home, _ := os.UserHomeDir()
	return []string{
		"/etc/nginx",
		"/etc/ssl/certs",
		filepath.Join(home, ".local/share/mkcert"),
		home,
	}
}

// Scan walks the given roots (shallowly) and parses every certificate it can read. Unreadable files
// are skipped in silence: on a machine where half of /etc needs root, a screen full of permission
// errors would bury the finding that matters.
func Scan(roots []string, maxDepth int) []Cert {
	var out []Cert
	seen := map[string]bool{}
	for _, root := range roots {
		base := strings.Count(filepath.Clean(root), string(os.PathSeparator))
		_ = filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
			if err != nil {
				if info != nil && info.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
			if info.IsDir() {
				if strings.Count(filepath.Clean(p), string(os.PathSeparator))-base > maxDepth {
					return filepath.SkipDir
				}
				return nil
			}
			switch strings.ToLower(filepath.Ext(p)) {
			case ".pem", ".crt", ".cer":
			default:
				return nil
			}
			if info.Size() > 1<<20 || seen[p] {
				return nil
			}
			seen[p] = true
			if c, ok := parse(p); ok {
				out = append(out, c)
			}
			return nil
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].NotAfter.Before(out[j].NotAfter) })
	return out
}

func parse(path string) (Cert, bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Cert{}, false
	}
	for len(b) > 0 {
		var blk *pem.Block
		blk, b = pem.Decode(b)
		if blk == nil {
			return Cert{}, false
		}
		if blk.Type != "CERTIFICATE" {
			continue
		}
		x, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			return Cert{}, false
		}
		return Cert{
			Path:     path,
			Subject:  name(x.Subject.String()),
			Issuer:   name(x.Issuer.String()),
			NotAfter: x.NotAfter,
			IsCA:     x.IsCA,
			SelfSign: x.Subject.String() == x.Issuer.String(),
			DNS:      x.DNSNames,
		}, true
	}
	return Cert{}, false
}

// name shortens an RFC 2253 distinguished name to its CN, which is the part anyone recognises.
func name(dn string) string {
	for _, part := range strings.Split(dn, ",") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "CN=") {
			return strings.TrimPrefix(part, "CN=")
		}
	}
	if len(dn) > 48 {
		return dn[:47] + "…"
	}
	return dn
}

// Summary renders the validity of a certificate as a phrase.
func (c Cert) Summary() string {
	d := c.Days()
	switch {
	case d < 0:
		return fmt.Sprintf("expired %d days ago", -d)
	case d < 30:
		return fmt.Sprintf("expires in %d days", d)
	default:
		return fmt.Sprintf("valid until %s", c.NotAfter.Format("2006-01-02"))
	}
}
