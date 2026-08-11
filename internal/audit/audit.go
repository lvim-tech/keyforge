// Package audit answers one question about this machine: which of the secrets lying around it
// would actually stop someone who already has a copy of the files.
//
// Every check here exists because it was needed in anger. A key with no passphrase is a key that
// works the moment it is copied. A key whose passphrase you also use to log in is a key that falls
// with the password hash. A public key still sitting in a remote authorized_keys is an open door
// that generating a replacement did nothing to close. The findings are ordered by that logic, not
// by how easy they were to compute.
package audit

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/lvim-tech/keyforge/internal/gpgkeys"
	"github.com/lvim-tech/keyforge/internal/passstore"
	"github.com/lvim-tech/keyforge/internal/sshkeys"
	"github.com/lvim-tech/keyforge/internal/sys"
)

// Severity ranks a finding.
type Severity int

const (
	Info Severity = iota
	Warn
	High
)

func (s Severity) String() string {
	switch s {
	case High:
		return "HIGH"
	case Warn:
		return "warn"
	default:
		return "info"
	}
}

// Finding is one thing worth knowing, with the action that resolves it.
type Finding struct {
	Severity Severity
	Subject  string // what it is about — a key name, a path
	Message  string // what is wrong
	Action   string // what to do about it
}

// Report is the whole sweep.
type Report struct {
	Findings []Finding
	Keys     int
	Hosts    int
	Hashed   int
	Root     bool // the sweep ran with enough privilege to read the system-wide parts
}

// Counts summarises the findings by severity.
func (r Report) Counts() (high, warn, info int) {
	for _, f := range r.Findings {
		switch f.Severity {
		case High:
			high++
		case Warn:
			warn++
		default:
			info++
		}
	}
	return
}

// Run performs the sweep.
func Run() Report {
	var rep Report
	rep.Root = os.Geteuid() == 0

	keys, err := sshkeys.ScanAll()
	if err != nil {
		rep.Findings = append(rep.Findings, Finding{High, strings.Join(sshkeys.Dirs(), ", "), "cannot read the directory: " + err.Error(), "check the permissions"})
		return rep
	}
	rep.Keys = len(keys)

	multi := len(sshkeys.Dirs()) > 1
	name := func(k sshkeys.Key) string {
		if multi {
			return k.Path
		}
		return k.Name
	}
	for _, k := range keys {
		if !k.Encrypted {
			rep.Findings = append(rep.Findings, Finding{
				High, name(k),
				"the private key has NO passphrase — a copy of the file is ready to use",
				"set one: keyforge → Keys → [p]",
			})
		}
		if weak, why := k.Weak(); weak {
			rep.Findings = append(rep.Findings, Finding{Warn, name(k), why, "generate a new ed25519 and remove the old one from the servers"})
		}
		if k.Format == "pem" {
			rep.Findings = append(rep.Findings, Finding{
				Warn, name(k),
				"old PEM format — the passphrase is protected by a single MD5 round, not bcrypt-KDF",
				"rewrite it with [p] (uses -o -a 100 and raises the protection)",
			})
		}
		if k.Mode&0o077 != 0 {
			rep.Findings = append(rep.Findings, Finding{
				High, name(k),
				fmt.Sprintf("mode %04o — the file is readable by other users", k.Mode),
				fmt.Sprintf("chmod 600 %s", k.Path),
			})
		}
		if k.InAgent {
			rep.Findings = append(rep.Findings, Finding{
				Info, name(k),
				"loaded in ssh-agent — while it is there the passphrase protects nothing: anyone who can reach the socket uses it",
				"ssh-add -d takes it out when you do not need it",
			})
		}
		if k.PubPath == "" {
			rep.Findings = append(rep.Findings, Finding{
				Info, name(k),
				"no .pub — it cannot be deployed or revoked without unlocking the key",
				"ssh-keygen -y -f " + k.Path + " > " + k.Path + ".pub",
			})
		}
	}

	// The directory itself: group- or world-reachable ~/.ssh undoes every file permission inside it.
	for _, dir := range sshkeys.Dirs() {
		if fi, err := os.Stat(dir); err == nil && fi.Mode().Perm()&0o077 != 0 {
			rep.Findings = append(rep.Findings, Finding{
				High, dir,
				fmt.Sprintf("mode %04o on the directory itself", fi.Mode().Perm()),
				"chmod 700 " + dir,
			})
		}
	}

	for _, dir := range sshkeys.Dirs() {
		rep.Findings = append(rep.Findings, authorizedKeys(dir, multi)...)
	}
	rep.Findings = append(rep.Findings, agentState()...)
	rep.Findings = append(rep.Findings, passStore()...)
	rep.Findings = append(rep.Findings, pinentry()...)
	rep.Findings = append(rep.Findings, systemChecks(rep.Root)...)

	hosts, hashed := sshkeys.KnownHosts()
	rep.Hosts, rep.Hashed = len(hosts), hashed

	return rep
}

// authorizedKeys inspects the local account's own authorized_keys — which keys may log IN here.
// A malformed line is worth flagging loudly: sshd skips it silently, so a typo in the key type
// means key authentication has quietly not worked for however long the typo has been there.
func authorizedKeys(dir string, multi bool) []Finding {
	var out []Finding
	path := filepath.Join(dir, "authorized_keys")
	subject := "authorized_keys"
	if multi {
		subject = path
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return out
	}
	valid := map[string]bool{
		"ssh-ed25519": true, "ssh-rsa": true, "ecdsa-sha2-nistp256": true,
		"ecdsa-sha2-nistp384": true, "ecdsa-sha2-nistp521": true, "ssh-dss": true,
		"sk-ssh-ed25519@openssh.com": true, "sk-ecdsa-sha2-nistp256@openssh.com": true,
	}
	n := 0
	for i, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		n++
		fields := strings.Fields(line)
		typ := fields[0]
		// Options may precede the key type; the type is then the second field.
		if !valid[typ] && len(fields) > 1 && valid[fields[1]] {
			typ = fields[1]
		}
		if !valid[typ] {
			out = append(out, Finding{
				High, fmt.Sprintf("%s:%d", subject, i+1),
				fmt.Sprintf("unknown key type %q — sshd skips the line silently, so logging in with this key does NOT work", typ),
				"fix the type (e.g. ssh-rsa) or remove the line",
			})
		}
	}
	if n > 0 {
		out = append(out, Finding{Info, subject, fmt.Sprintf("%d keys can log into this account", n), "look through them — do you recognise every one"})
	}
	return out
}

// passStore audits the password store as a single secret, which is what it is.
//
// Every entry in it is encrypted to one GPG key, so that key's passphrase is the store's master
// password and the only thing standing between a copied ~/.password-store and all of it. `pass`
// itself never mentions this — it will happily run on a key with no passphrase and say nothing —
// which is precisely why it belongs in an audit rather than in the documentation.
//
// The passphrase question is answered by gpg-agent, not by looking at the key file. There is no
// honest way to read protection out of the file, and a guess here would be a guess about whether
// the user's passwords are protected.
func passStore() []Finding {
	if !passstore.Available() {
		return nil
	}
	var out []Finding
	recipient := passstore.Recipient()
	prot, keyID := gpgkeys.StoreProtection(recipient)
	entries, _ := passstore.Entries()
	subject := "pass"

	switch {
	case !prot.Known:
		out = append(out, Finding{
			Info, subject,
			"could not verify whether the store's GPG key has a passphrase (the agent did not answer)",
			"gpg-connect-agent 'KEYINFO --list' /bye",
		})
	case !prot.Protected:
		out = append(out, Finding{
			High, subject,
			fmt.Sprintf("the store's GPG key (%s) has NO passphrase — a copy of %s opens immediately, with all %d entries",
				shortID(keyID), passstore.Dir(), len(entries)),
			"gpg --change-passphrase " + keyID,
		})
	case prot.Cached:
		// Not a defect — it is what an agent is for — but it is the difference between the third and
		// fourth row of the README's table, and it is true right now rather than in general.
		ttl := gpgkeys.AgentCacheTTL()
		out = append(out, Finding{
			Warn, subject,
			fmt.Sprintf("the store is unlocked in the gpg agent right now — for up to %s any process that can reach the socket reads every entry without a passphrase",
				ttl.Default),
			"gpgconf --reload gpg-agent ends the session; default-cache-ttl in ~/.gnupg/gpg-agent.conf decides how long",
		})
	}

	// The store directory itself. The files are ciphertext, so the permissions are not the last line
	// of defence — but the NAMES are not encrypted, and a world-readable store publishes the list of
	// every site you have an account with.
	if fi, err := os.Stat(passstore.Dir()); err == nil && fi.Mode().Perm()&0o077 != 0 {
		out = append(out, Finding{
			Warn, passstore.Dir(),
			fmt.Sprintf("mode %04o — the contents are encrypted, but the entry names are not", fi.Mode().Perm()),
			"chmod -R go-rwx " + passstore.Dir(),
		})
	}
	return out
}

// pinentry audits the prompt itself — the last link in the chain and the least examined one.
//
// Everything else here asks whether a secret is protected. This asks whether the question
// can be put to you at all, and whether the program putting it is one you want holding the
// answer. On this machine both went wrong at once and neither made a sound.
func pinentry() []Finding {
	if !gpgkeys.Available() {
		return nil
	}
	p := gpgkeys.CurrentPinentry()
	var out []Finding

	if p.Path == "" {
		return []Finding{{
			High, "pinentry",
			"none is configured and none is on PATH — nothing can ask for a passphrase, so every gpg operation needing one fails",
			"install one and set pinentry-program in " + p.ConfPath,
		}}
	}

	name := filepath.Base(p.Path)

	if p.X11Only && gpgkeys.SessionIsWayland() {
		out = append(out, Finding{
			High, "pinentry",
			name + " is X11-only and this session is Wayland with no DISPLAY — it cannot open a window, so anything started without a terminal (a launcher, a browser, a service) gets no prompt at all and fails without saying why",
			"switch to one that speaks Wayland: pinentry-program /usr/bin/pinentry-qt in " + p.ConfPath,
		})
	}

	if p.LinksKeyring && gpgkeys.KeyringRunning() {
		out = append(out, Finding{
			Warn, "pinentry",
			name + " links libsecret and a keyring daemon is running, so it can offer to store the passphrase — which would leave the store guarded by your login password rather than by something you know",
			"decline that offer, or use a pinentry with no keyring support",
		})
	}

	if len(out) == 0 {
		src := "found on PATH"
		if p.FromConfig {
			src = "set in " + p.ConfPath
		}
		out = append(out, Finding{Info, "pinentry", name + " will ask (" + src + ")", ""})
	}
	return out
}

// shortID trims a fingerprint to the part a person reads.
func shortID(id string) string {
	if len(id) > 16 {
		return id[len(id)-16:]
	}
	if id == "" {
		return "?"
	}
	return id
}

// agentState reports what the running agent currently holds.
func agentState() []Finding {
	res, err := sys.Run("ssh-add", "-l")
	if err != nil {
		return nil
	}
	if res.Code == 1 && strings.Contains(res.Stdout+res.Stderr, "no identities") {
		return nil
	}
	if res.Code == 2 {
		return nil // no agent running
	}
	n := 0
	for _, l := range strings.Split(res.Stdout, "\n") {
		if strings.TrimSpace(l) != "" {
			n++
		}
	}
	if n == 0 {
		return nil
	}
	return []Finding{{
		Warn, "ssh-agent",
		fmt.Sprintf("%d keys are unlocked in the agent — their passphrases are protecting nothing right now", n),
		"ssh-add -D clears the agent",
	}}
}

// systemChecks covers the parts that live outside the home directory. They need root, and when it
// is missing the check says so instead of reporting a clean result it could not verify — a silent
// pass is worse than an admitted gap.
func systemChecks(root bool) []Finding {
	var out []Finding

	if !root {
		out = append(out, Finding{
			Info, "system",
			"without root: /etc/shadow and the sshd configuration cannot be checked",
			"run `sudo keyforge --audit` for the full sweep",
		})
		return out
	}

	// Password hashing: $6$ is sha512crypt, which a GPU grinds about a million times faster than
	// yescrypt. A stolen /etc/shadow with $6$ hashes is a very different problem from one with $y$.
	if b, err := os.ReadFile("/etc/shadow"); err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			parts := strings.SplitN(line, ":", 3)
			if len(parts) < 2 || len(parts[1]) < 3 {
				continue
			}
			if strings.HasPrefix(parts[1], "$6$") {
				out = append(out, Finding{
					Warn, "shadow:" + parts[0],
					"the password uses sha512crypt ($6$) — the fastest of the current schemes to crack",
					"ENCRYPT_METHOD YESCRYPT in /etc/login.defs, then passwd " + parts[0],
				})
			}
		}
	}

	if res, err := sys.Run("sshd", "-T"); err == nil && res.OK() {
		for _, line := range strings.Split(res.Stdout, "\n") {
			f := strings.Fields(line)
			if len(f) != 2 {
				continue
			}
			switch f[0] {
			case "permitrootlogin":
				if f[1] != "no" {
					out = append(out, Finding{High, "sshd", "PermitRootLogin " + f[1] + " — root can log in over SSH", "PermitRootLogin no in /etc/ssh/sshd_config"})
				}
			case "passwordauthentication":
				if f[1] == "yes" {
					out = append(out, Finding{Warn, "sshd", "PasswordAuthentication yes — passwords can be guessed from outside", "move to keys and turn it off"})
				}
			case "permitemptypasswords":
				if f[1] == "yes" {
					out = append(out, Finding{High, "sshd", "PermitEmptyPasswords yes", "turn it off now"})
				}
			}
		}
	}
	return out
}
