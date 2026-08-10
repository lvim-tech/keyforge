// Package sshkeys discovers and describes the SSH keys on this machine.
//
// The one thing worth stating plainly, because getting it wrong is what this package exists to
// prevent: THERE IS NO WAY TO TELL WHETHER A KEY IS ENCRYPTED BY READING IT AS TEXT. The obvious
// test — grepping the file for "ENCRYPTED" — works only for the old PEM format. Every key written
// by a current ssh-keygen uses the OpenSSH container, where the KDF name lives inside the base64
// blob, so the grep silently answers "not encrypted" for every modern key.
//
// The only honest test is to ask ssh-keygen to derive the public key with an empty passphrase and
// see whether it agrees:
//
//	ssh-keygen -y -P "" -f <key>   exit 0 → no passphrase   exit != 0 → encrypted
//
// That is what Scan does, and it is why an audit here can be trusted.
package sshkeys

import (
	"bufio"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/lvim-tech/keyforge/internal/sys"
)

// Key is one private key found on disk, with everything the UI needs to describe it.
type Key struct {
	Path        string // absolute path to the private key
	Name        string // basename, what the user calls it
	Type        string // ED25519 / RSA / ECDSA / DSA
	Bits        int    // key size, 0 when ssh-keygen could not say
	Fingerprint string // SHA256:… as ssh-keygen prints it
	Comment     string // the trailing comment of the public key
	Encrypted   bool   // has a passphrase (see the package comment for how this is decided)
	Format      string // "openssh" (modern container) or "pem" (legacy)
	Mode        os.FileMode
	Modified    time.Time
	Hosts       []string // hosts from ~/.ssh/config that point IdentityFile at this key
	InAgent     bool     // currently loaded in the running ssh-agent
	PubPath     string   // the .pub beside it, when present
	Dir         string   // which .ssh directory it was found in — matters under sudo, where two are scanned
}

// Weak reports whether the key's algorithm or size is no longer worth trusting, with a reason.
// RSA below 3072 bits and everything DSA are the two that matter in practice; ECDSA is flagged
// softly because its NIST curves are merely unfashionable, not broken.
func (k Key) Weak() (bool, string) {
	switch strings.ToUpper(k.Type) {
	case "DSA":
		return true, "DSA is obsolete and removed from OpenSSH"
	case "RSA":
		if k.Bits > 0 && k.Bits < 3072 {
			return true, fmt.Sprintf("RSA %d bits — below the recommended 3072", k.Bits)
		}
	case "ECDSA":
		return true, "ECDSA (NIST curves) — ed25519 is preferable"
	}
	return false, ""
}

// Age returns how long ago the key file was last written.
func (k Key) Age() time.Duration { return time.Since(k.Modified) }

var (
	privateHeader = regexp.MustCompile(`-----BEGIN (OPENSSH|RSA|DSA|EC|ENCRYPTED)? ?PRIVATE KEY-----`)
	// ssh-keygen -lf prints: "<bits> <fingerprint> <comment> (<TYPE>)"
	fingerLine = regexp.MustCompile(`^(\d+)\s+(\S+)\s+(.*)\s+\(([A-Z0-9-]+)\)\s*$`)
)

// Dir returns the SSH directory for the current user.
func Dir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ".ssh"
	}
	return filepath.Join(home, ".ssh")
}

// Dirs returns every SSH directory worth auditing in this invocation.
//
// Under sudo that is TWO of them. Root's home holds almost never anything, so `sudo keyforge
// --audit` reported "0 keys" and looked like a clean bill of health for a machine with eight
// unexamined keys sitting in the invoking user's home. A privileged run that sees less than an
// unprivileged one is worse than useless — it is reassuring about the wrong thing.
func Dirs() []string {
	out := []string{Dir()}
	if u := os.Getenv("SUDO_USER"); u != "" && os.Geteuid() == 0 {
		if usr, err := user.Lookup(u); err == nil {
			d := filepath.Join(usr.HomeDir, ".ssh")
			if d != out[0] {
				if _, err := os.Stat(d); err == nil {
					out = append(out, d)
				}
			}
		}
	}
	return out
}

// ScanAll describes the keys in every directory Dirs reports.
func ScanAll() ([]Key, error) {
	var all []Key
	var firstErr error
	for _, d := range Dirs() {
		keys, err := scanDir(d)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		all = append(all, keys...)
	}
	if len(all) == 0 && firstErr != nil {
		return nil, firstErr
	}
	sort.Slice(all, func(i, j int) bool { return all[i].Path < all[j].Path })
	return all, nil
}

// Scan walks the SSH directory and describes every private key it finds. Files that merely look
// like keys (known_hosts, config, *.pub) are skipped by content, not by name — a key called
// "netera" with no extension is exactly as real as one called id_ed25519.
func Scan() ([]Key, error) { return scanDir(Dir()) }

func scanDir(dir string) ([]Key, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	hostMap := identityHosts(dir)
	agent := agentFingerprints()

	var keys []Key
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		path := filepath.Join(dir, e.Name())
		if !looksPrivate(path) {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		k := Key{
			Path:     path,
			Name:     e.Name(),
			Mode:     info.Mode().Perm(),
			Modified: info.ModTime(),
			Format:   formatOf(path),
		}
		describe(&k)
		k.Encrypted = isEncrypted(path)
		k.Dir = dir
		if _, err := os.Stat(path + ".pub"); err == nil {
			k.PubPath = path + ".pub"
		}
		k.Hosts = hostMap[path]
		if k.Fingerprint != "" {
			_, k.InAgent = agent[k.Fingerprint]
		}
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i].Name < keys[j].Name })
	return keys, nil
}

// looksPrivate reports whether the first non-empty line is a private key header.
func looksPrivate(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	// A key header sits on the first line; cap the scan so a 28 MB history file is not read.
	for i := 0; i < 3 && sc.Scan(); i++ {
		if privateHeader.MatchString(sc.Text()) {
			return true
		}
	}
	return false
}

// formatOf distinguishes the modern OpenSSH container from the legacy PEM encodings. It matters
// because only the OpenSSH container uses bcrypt-KDF for the passphrase; a PEM key's passphrase is
// protected by a single MD5 pass, which is why re-writing old keys is worth doing.
func formatOf(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return "?"
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	if sc.Scan() {
		if strings.Contains(sc.Text(), "OPENSSH PRIVATE KEY") {
			return "openssh"
		}
		return "pem"
	}
	return "?"
}

// isEncrypted asks ssh-keygen to derive the public key with an empty passphrase. Success means the
// file is readable without a secret. See the package comment for why nothing simpler works.
func isEncrypted(path string) bool {
	res, err := sys.Run("ssh-keygen", "-y", "-P", "", "-f", path)
	if err != nil {
		return true // cannot tell → assume protected rather than claim it is not
	}
	return !res.OK()
}

// describe fills in type, bits, fingerprint and comment from `ssh-keygen -lf`, which works on the
// private key even when it is encrypted (it reads the public half stored alongside it).
func describe(k *Key) {
	res, err := sys.Run("ssh-keygen", "-lf", k.Path)
	if err != nil || !res.OK() {
		return
	}
	m := fingerLine.FindStringSubmatch(strings.TrimSpace(res.Stdout))
	if m == nil {
		return
	}
	k.Bits, _ = strconv.Atoi(m[1])
	k.Fingerprint = m[2]
	k.Comment = strings.TrimSpace(m[3])
	k.Type = m[4]
}

// identityHosts maps a key path to the Host aliases in ~/.ssh/config that select it. This is what
// turns "you have eight keys" into "this key opens these machines" — the difference between an
// inventory and something you can act on when a key has to be rotated.
func identityHosts(dir string) map[string][]string {
	out := map[string][]string{}
	f, err := os.Open(filepath.Join(dir, "config"))
	if err != nil {
		return out
	}
	defer func() { _ = f.Close() }()

	var current []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		switch strings.ToLower(fields[0]) {
		case "host":
			current = fields[1:]
		case "identityfile":
			p := expand(dir, fields[1])
			out[p] = append(out[p], current...)
		}
	}
	return out
}

// expand resolves ~ and makes the path absolute the way ssh itself does.
func expand(dir, p string) string {
	p = strings.Trim(p, `"`)
	if strings.HasPrefix(p, "~/") {
		home, err := os.UserHomeDir()
		if err == nil {
			return filepath.Join(home, p[2:])
		}
	}
	if !filepath.IsAbs(p) {
		return filepath.Join(dir, p)
	}
	return p
}

// agentFingerprints returns the fingerprints currently held by ssh-agent. A key loaded in the agent
// is usable by anything that can reach the agent socket — including, on a compromised machine, root.
// That is the one path a passphrase does not protect, so the UI shows it.
func agentFingerprints() map[string]bool {
	out := map[string]bool{}
	res, err := sys.Run("ssh-add", "-l")
	if err != nil || !res.OK() {
		return out
	}
	for _, line := range strings.Split(res.Stdout, "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			out[fields[1]] = true
		}
	}
	return out
}

// PublicKey returns the contents of the .pub beside the key, deriving it when the file is missing
// and the key is unencrypted. An encrypted key with no .pub cannot be read without the passphrase,
// and that is reported rather than prompted for behind the user's back.
func PublicKey(k Key) (string, error) {
	if k.PubPath != "" {
		b, err := os.ReadFile(k.PubPath)
		if err == nil {
			return strings.TrimSpace(string(b)), nil
		}
	}
	if k.Encrypted {
		return "", fmt.Errorf("no %s.pub, and the key has a passphrase", k.Name)
	}
	res, err := sys.Run("ssh-keygen", "-y", "-P", "", "-f", k.Path)
	if err != nil || !res.OK() {
		return "", fmt.Errorf("cannot derive the public key")
	}
	return strings.TrimSpace(res.Stdout), nil
}

// Fingerprints returns the SHA256 and MD5 forms of a key's fingerprint. Both are useful: SHA256 is
// what OpenSSH prints today, MD5 is what older servers still write into their logs, and hunting a
// stolen key through old logs needs the form those logs used.
func Fingerprints(k Key) (sha, md5 string) {
	if r, err := sys.Run("ssh-keygen", "-lf", k.Path); err == nil && r.OK() {
		if f := strings.Fields(r.Stdout); len(f) >= 2 {
			sha = f[1]
		}
	}
	if r, err := sys.Run("ssh-keygen", "-lf", k.Path, "-E", "md5"); err == nil && r.OK() {
		if f := strings.Fields(r.Stdout); len(f) >= 2 {
			md5 = f[1]
		}
	}
	return
}
