package sshkeys

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/lvim-tech/keyforge/internal/sys"
)

// Spec describes a key to be created.
type Spec struct {
	Name    string // file name inside ~/.ssh
	Type    string // ed25519 (default) or rsa
	Bits    int    // RSA only
	Comment string
	Rounds  int // bcrypt-KDF rounds for the passphrase; higher = slower to attack offline
}

// DefaultSpec is what the tool proposes: ed25519, and 100 KDF rounds rather than the built-in 16.
// The rounds only cost time when the key is unlocked — a tenth of a second for you, a hundredfold
// increase in the cost of grinding the passphrase for anyone who steals the file.
func DefaultSpec() Spec {
	host, _ := os.Hostname()
	user := os.Getenv("USER")
	return Spec{
		Type:    "ed25519",
		Rounds:  100,
		Comment: fmt.Sprintf("%s@%s", user, host),
	}
}

// Path is the absolute location the key will be written to.
func (s Spec) Path() string { return filepath.Join(Dir(), s.Name) }

// Exists reports whether something already occupies that path — ssh-keygen would otherwise ask,
// and a prompt hidden behind a TUI is how a key gets silently overwritten.
func (s Spec) Exists() bool {
	_, err := os.Stat(s.Path())
	return err == nil
}

// GenerateCmd builds the ssh-keygen invocation for a new key.
//
// There is deliberately no -N: the passphrase is NOT passed on the command line. ssh-keygen asks
// for it on the terminal it has been handed, so the secret never appears in this process, in argv,
// or in /proc/<pid>/cmdline where any local user could read it while the command runs.
func GenerateCmd(s Spec) *exec.Cmd {
	args := []string{"-t", s.Type}
	if s.Type == "rsa" && s.Bits > 0 {
		args = append(args, "-b", fmt.Sprint(s.Bits))
	}
	if s.Rounds > 0 {
		args = append(args, "-a", fmt.Sprint(s.Rounds))
	}
	if s.Comment != "" {
		args = append(args, "-C", s.Comment)
	}
	args = append(args, "-f", s.Path())
	return sys.Interactive("ssh-keygen", args...)
}

// ChangePassphraseCmd rewrites a key with a new passphrase. `-o -a` forces the modern OpenSSH
// container with a strong KDF even when the key was written in the old PEM format, so changing the
// passphrase on a legacy key upgrades its protection at the same time.
func ChangePassphraseCmd(k Key, rounds int) *exec.Cmd {
	if rounds <= 0 {
		rounds = 100
	}
	return sys.Interactive("ssh-keygen", "-p", "-o", "-a", fmt.Sprint(rounds), "-f", k.Path)
}

// DeployCmd installs a key's public half into a remote account's authorized_keys.
func DeployCmd(k Key, target string) (*exec.Cmd, error) {
	pub := k.PubPath
	if pub == "" {
		return nil, fmt.Errorf("%s.pub is missing", k.Name)
	}
	if !sys.Have("ssh-copy-id") {
		return nil, fmt.Errorf("ssh-copy-id is not on this machine")
	}
	return sys.Interactive("ssh-copy-id", "-i", pub, target), nil
}

// RevokeCmd removes a public key from a remote account's authorized_keys.
//
// This is the half of rotation people skip. Generating a new key changes nothing on its own — the
// old public key keeps opening every machine it was ever installed on, and it will go on doing so
// for years unless something takes it out. The remote script matches the key BLOB (the base64
// body), not the whole line, because the comment at the end differs from host to host.
func RevokeCmd(pubLine, target string) (*exec.Cmd, error) {
	blob := keyBlob(pubLine)
	if blob == "" {
		return nil, fmt.Errorf("cannot parse the public key")
	}
	script := fmt.Sprintf(`f="$HOME/.ssh/authorized_keys"; `+
		`[ -f "$f" ] || { echo "no authorized_keys"; exit 0; }; `+
		`n=$(grep -cF %s "$f" 2>/dev/null || true); `+
		`if [ "${n:-0}" -eq 0 ]; then echo "the key is not there"; exit 0; fi; `+
		`cp "$f" "$f.keyforge.bak"; `+
		`grep -vF %s "$f.keyforge.bak" > "$f"; `+
		`echo "lines removed: $n (backup: $f.keyforge.bak)"`,
		shellQuote(blob), shellQuote(blob))
	return sys.Interactive("ssh", "-t", target, script), nil
}

// AuthorizedKeysCmd lists a remote account's authorized_keys with fingerprints, so a stolen key can
// be hunted across the machines it might still open.
func AuthorizedKeysCmd(target string) *exec.Cmd {
	script := `f="$HOME/.ssh/authorized_keys"; ` +
		`[ -f "$f" ] || { echo "no authorized_keys"; exit 0; }; ` +
		`ssh-keygen -lf "$f" 2>/dev/null || cat "$f"`
	return sys.Interactive("ssh", "-t", target, script)
}

// keyBlob extracts the base64 body of a public key line — the part that identifies the key itself,
// independent of type prefix and trailing comment.
func keyBlob(line string) string {
	fields := strings.Fields(strings.TrimSpace(line))
	if len(fields) < 2 {
		return ""
	}
	return fields[1]
}

// shellQuote wraps a string for a POSIX shell, escaping embedded single quotes. Used only for the
// remote script; nothing on this machine is ever handed to a shell.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// KnownHosts returns the host patterns recorded in known_hosts. Hashed entries cannot be reversed,
// so those are reported as such rather than quietly omitted — a machine you cannot name is still a
// machine your key may open.
func KnownHosts() (hosts []string, hashed int) {
	seen := map[string]bool{}
	for _, dir := range Dirs() {
		h, n := knownHostsIn(dir, seen)
		hosts = append(hosts, h...)
		hashed += n
	}
	return hosts, hashed
}

func knownHostsIn(dir string, seen map[string]bool) (hosts []string, hashed int) {
	b, err := os.ReadFile(filepath.Join(dir, "known_hosts"))
	if err != nil {
		return nil, 0
	}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		first := strings.Fields(line)
		if len(first) == 0 {
			continue
		}
		if strings.HasPrefix(first[0], "|1|") {
			hashed++
			continue
		}
		for _, h := range strings.Split(first[0], ",") {
			if h != "" && !seen[h] {
				seen[h] = true
				hosts = append(hosts, h)
			}
		}
	}
	return hosts, hashed
}

// ConfigHosts returns the Host aliases declared in ~/.ssh/config together with their real hostname,
// which is what the deploy and revoke actions offer as targets.
func ConfigHosts() map[string]string {
	out := map[string]string{}
	f, err := os.Open(filepath.Join(Dir(), "config"))
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
			for _, h := range current {
				if !strings.ContainsAny(h, "*?") {
					if _, ok := out[h]; !ok {
						out[h] = ""
					}
				}
			}
		case "hostname":
			for _, h := range current {
				if !strings.ContainsAny(h, "*?") {
					out[h] = fields[1]
				}
			}
		}
	}
	return out
}
