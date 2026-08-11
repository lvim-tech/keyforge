package gpgkeys

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
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

// ClearCache makes gpg-agent forget every passphrase it is holding.
//
// This is the operation that gives the screen lock its meaning. Locking a UI while the agent still
// remembers protects nothing: the next `gpg` call signs or decrypts without a prompt, so the lock
// opens on an empty keypress and `pass show` in another terminal never even notices. After this,
// the passphrase has to be entered again — by keyforge to unlock, and by anything else that wants
// the store.
//
// It clears every key rather than one, which is right for a lock — locking your session should not
// leave a different key of yours still open — and is the reason it is a setting rather than
// unconditional: the agent is shared with your other terminals and with signed commits.
//
// CLEAR_PASSPHRASE, addressed by keygrip — the agent's own cache id for a private key — rather than
// `gpgconf --reload gpg-agent`. A reload does drop the caches, but it does so as a side effect of
// re-reading the configuration file: it is a request to reload, and forgetting is not what it is
// for. CLEAR_PASSPHRASE says the thing that is meant, key by key, and answers OK or does not.
//
// THE RESULT IS VERIFIED RATHER THAN ASSUMED, and that is the part that matters. This lock once
// announced it had shut the store and then opened again without asking for anything: the clearing
// step had been called, its return value was nil, and nobody had ever checked whether the agent
// actually let go. "I asked the agent to forget" and "the agent forgot" are different claims, and
// only the second one is worth putting on a screen that says the store is locked.
func ClearCache() error {
	if !sys.Have("gpg-connect-agent") {
		return fmt.Errorf("gpg-connect-agent is not on this machine")
	}
	before := Protections()
	var failed []string
	for grip, p := range before {
		if !p.Cached {
			continue
		}
		res, err := sys.Run("gpg-connect-agent", "CLEAR_PASSPHRASE --mode=normal "+grip, "/bye")
		if err != nil || !res.OK() {
			failed = append(failed, grip[:8])
		}
	}
	if len(failed) > 0 {
		return fmt.Errorf("the agent would not forget %s", strings.Join(failed, ", "))
	}
	// Ask again. A cache that is still holding something after being told to let go is worth
	// reporting loudly: the lock is then weaker than the screen it just drew says it is.
	var still []string
	for grip, p := range Protections() {
		if p.Cached {
			still = append(still, grip[:8])
		}
	}
	if len(still) > 0 {
		sort.Strings(still)
		return fmt.Errorf("still cached after clearing: %s", strings.Join(still, ", "))
	}
	return nil
}

// AnyCached reports whether the agent is currently holding any passphrase at all.
//
// Used to tell the difference between a lock that will actually ask something and one that will
// open silently, so the interface can say which of the two just happened instead of implying the
// stronger one.
func AnyCached() bool {
	for _, p := range Protections() {
		if p.Cached {
			return true
		}
	}
	return false
}

// NewChallenge writes a scrap of ciphertext that only the store's key can open.
//
// The unlock has to prove the user can DECRYPT, not sign, and the difference is not academic: a
// `pass` entry is encrypted to the encryption subkey, and on a normal keyring that subkey cannot
// sign at all — asking it to produces "signing failed" and an unlock that can never succeed. So the
// challenge is a message encrypted to the recipient, and opening it is exactly the capability the
// store depends on.
//
// Encrypting needs no passphrase, so this can be prepared at the moment of locking. The file goes
// into /dev/shm, which is RAM: it is only ciphertext and nothing is lost if it vanishes, but there
// is no reason for it to outlive the process on a disk either.
func NewChallenge(recipient string) (string, error) {
	if recipient == "" {
		return "", fmt.Errorf("no recipient to build a challenge for")
	}
	dir := os.TempDir()
	if fi, err := os.Stat("/dev/shm"); err == nil && fi.IsDir() {
		dir = "/dev/shm"
	}
	f, err := os.CreateTemp(dir, "keyforge-unlock-*.gpg")
	if err != nil {
		return "", err
	}
	path := f.Name()
	_ = f.Close()
	if err := os.Chmod(path, 0o600); err != nil {
		_ = os.Remove(path)
		return "", err
	}

	cmd := exec.Command("gpg", "--quiet", "--batch", "--yes", "--encrypt",
		"--recipient", recipient, "--trust-model", "always", "--output", path)
	cmd.Stdin = strings.NewReader("keyforge-unlock")
	errb := &strings.Builder{}
	cmd.Stderr = errb
	if err := cmd.Run(); err != nil {
		_ = os.Remove(path)
		return "", fmt.Errorf("gpg --encrypt: %s", firstLine(errb.String(), err.Error()))
	}
	return path, nil
}

// UnlockCmd opens the challenge, which gpg cannot do without the passphrase.
//
// The plaintext is thrown away; the point is not the output but that gpg had to obtain the
// passphrase to produce it. keyforge never handles that passphrase — pinentry asks, gpg keeps it,
// and this process learns only whether the exit code was zero.
//
// Interactive, because pinentry wants the real terminal; the caller hands it to tea.ExecProcess
// like every other passphrase-bearing command in this program.
//
// stderr is captured rather than left on the screen. gpg explains itself there — "No pinentry",
// "Inappropriate ioctl for device", "Bad passphrase" are three completely different problems — but
// the TUI repaints the moment gpg exits, so anything printed is gone before it can be read. Without
// this the only thing left is an exit code, which says nothing about which of the three it was.
func UnlockCmd(challenge string, stderr io.Writer) *exec.Cmd {
	// The plaintext goes to stdout and is discarded there, NOT to --output /dev/null. gpg writes
	// through a temporary "<output>.part" and renames it into place, so asking it to write to
	// /dev/null makes it try to create /dev/null.part inside /dev — which fails with "Permission
	// denied" and no prompt ever appears. Discarding the stream sidesteps the temporary file
	// entirely, and pinentry is unaffected: it draws on the terminal named by GPG_TTY, not on
	// gpg's stdout.
	cmd := sys.Interactive("gpg", "--decrypt", challenge)
	cmd.Stdout = io.Discard
	cmd.Stderr = stderr
	return cmd
}

// firstLine reduces a tool's complaint to the part worth putting on a one-line status bar.
func firstLine(s, fallback string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return fallback
	}
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	return s
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

// SetCacheTTL writes the two cache lifetimes into gpg-agent.conf and reloads the agent.
//
// It is written into gpg's own configuration rather than kept in keyforge's, because gpg-agent is
// what enforces it. A number that keyforge remembered and the agent never read would be a setting
// describing a protection that is not in force — the one kind of dishonesty this program is built
// to avoid.
//
// Existing lines are rewritten in place and the rest of the file is left exactly as it was: this is
// somebody's gpg configuration, and a tool that rewrites it wholesale to change two numbers will
// eventually delete something that mattered.
func SetCacheTTL(defaultTTL, maxTTL time.Duration) error {
	path := agentConfPath()
	if path == "" {
		return fmt.Errorf("cannot locate gpg-agent.conf")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	var lines []string
	if b, err := os.ReadFile(path); err == nil {
		lines = strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	} else if !os.IsNotExist(err) {
		return err
	}

	want := map[string]int{}
	if defaultTTL > 0 {
		want["default-cache-ttl"] = int(defaultTTL.Seconds())
		// The SSH side of the agent has its own pair of settings, and leaving them behind is how a
		// key stays open for two hours after the store has been shut for ten minutes.
		want["default-cache-ttl-ssh"] = int(defaultTTL.Seconds())
	}
	if maxTTL > 0 {
		want["max-cache-ttl"] = int(maxTTL.Seconds())
		want["max-cache-ttl-ssh"] = int(maxTTL.Seconds())
	}

	seen := map[string]bool{}
	for i, l := range lines {
		key, _, ok := strings.Cut(strings.TrimSpace(l), " ")
		if !ok {
			continue
		}
		if v, isOurs := want[key]; isOurs {
			lines[i] = fmt.Sprintf("%s %d", key, v)
			seen[key] = true
		}
	}
	for _, key := range []string{"default-cache-ttl", "default-cache-ttl-ssh", "max-cache-ttl", "max-cache-ttl-ssh"} {
		if v, isOurs := want[key]; isOurs && !seen[key] {
			lines = append(lines, fmt.Sprintf("%s %d", key, v))
		}
	}

	out := strings.Join(lines, "\n") + "\n"
	if err := os.WriteFile(path, []byte(strings.TrimLeft(out, "\n")), 0o600); err != nil {
		return err
	}
	// A written file the agent has not read is still just a file — and CLEAR_PASSPHRASE, which
	// this used to call, does not make it read one. It flushes the cached passphrases and
	// leaves the running agent on its old lifetimes, so the numbers written here were never in
	// force; EnsureCacheTTL then compared against the FILE, found them already there, and
	// reported "unchanged" for ever. `gpgconf --reload gpg-agent` is the command that makes the
	// agent re-read its configuration, and it is what this program's own audit tab tells the
	// user to run.
	if res, err := sys.Run("gpgconf", "--reload", "gpg-agent"); err != nil {
		return err
	} else if !res.OK() {
		return fmt.Errorf("gpgconf --reload gpg-agent: %s", strings.TrimSpace(res.Stderr))
	}
	return nil
}

// EnsureCacheTTL applies the configured lifetimes only when they are not already in force.
//
// The check is the whole point. SetCacheTTL reloads the agent, and reloading drops every cached
// passphrase — so writing the same two numbers on every launch would mean keyforge silently logged
// you out of your own store each time it started. Reported as changed/unchanged rather than done,
// because "your agent was just cleared" is something the caller has to be able to say.
func EnsureCacheTTL(defaultTTL, maxTTL time.Duration) (changed bool, err error) {
	if defaultTTL <= 0 && maxTTL <= 0 {
		return false, nil
	}
	cur := AgentCacheTTL()
	if (defaultTTL <= 0 || cur.Default == defaultTTL) && (maxTTL <= 0 || cur.Max == maxTTL) {
		return false, nil
	}
	return true, SetCacheTTL(defaultTTL, maxTTL)
}

func agentConfPath() string {
	if home := os.Getenv("GNUPGHOME"); home != "" {
		return filepath.Join(home, "gpg-agent.conf")
	}
	h, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(h, ".gnupg", "gpg-agent.conf")
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
