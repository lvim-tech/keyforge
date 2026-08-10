// Package passstore is keyforge's bridge to `pass`, the standard Unix password manager.
//
// WHY KEYFORGE DOES NOT STORE ANYTHING ITSELF. A password store is a small idea with a large
// surface: key derivation, an on-disk format, atomic writes, memory that must not be swapped or
// dumped, a master secret whose handling decides everything. Writing another one would be the
// opposite of "a layer over the tools" — it would be a new, unreviewed piece of cryptography sitting
// under the very secrets it claims to protect. `pass` already exists, is GPG underneath, and is on
// this machine. keyforge writes into it and gets out of the way.
//
// WHAT THIS BUYS, AND WHAT IT DOES NOT. The store is ciphertext at rest: a stolen disk, a backup, a
// second user on the machine — none of them get anything. What it cannot survive is root on the
// same machine WHILE the secret is unlocked, because at that moment the plaintext exists in a
// process and the agent socket answers to whoever can reach it. That is not a flaw in `pass`; it is
// true of ssh-agent, of gnome-keyring, and of anything that could be written here. The only design
// that beats it keeps the key off the machine entirely, on a hardware token.
package passstore

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/lvim-tech/keyforge/internal/sys"
)

// Available reports whether `pass` is installed and initialised.
func Available() bool {
	if !sys.Have("pass") {
		return false
	}
	_, err := os.Stat(filepath.Join(dir(), ".gpg-id"))
	return err == nil
}

// dir is the password store location, honouring PASSWORD_STORE_DIR like pass itself.
func dir() string {
	if d := os.Getenv("PASSWORD_STORE_DIR"); d != "" {
		return d
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ".password-store"
	}
	return filepath.Join(home, ".password-store")
}

// Dir is the store location, for showing where entries actually live.
func Dir() string { return dir() }

// Recipient returns the GPG id the store encrypts to, for display.
func Recipient() string {
	b, err := os.ReadFile(filepath.Join(dir(), ".gpg-id"))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// Entry is one record: its full store path, the folder it sits in, and when it was last written.
//
// The split is kept here rather than in the view because the folder is not decoration — it is how
// a store with a hundred site logins stays readable, and every caller wants the same split.
type Entry struct {
	Name     string // full path in the store, without the .gpg suffix
	Folder   string // "" for a top-level entry
	Leaf     string // the last segment
	Modified time.Time
}

// Entries returns every record in the store, sorted by path.
//
// Only names and timestamps are read; nothing is decrypted, so this never prompts for a passphrase
// and never touches a secret. That is what makes it safe to run on startup for a tab the user may
// never open.
func Entries() ([]Entry, error) {
	root := dir()
	var out []Entry
	err := filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		// The store is frequently a git repository; its object database is not password data.
		if info.IsDir() {
			if info.Name() == ".git" || info.Name() == ".gnupg" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(p, ".gpg") {
			return nil
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return nil
		}
		name := strings.TrimSuffix(filepath.ToSlash(rel), ".gpg")
		folder, leaf := path.Split(name)
		out = append(out, Entry{
			Name:     name,
			Folder:   strings.TrimSuffix(folder, "/"),
			Leaf:     leaf,
			Modified: info.ModTime(),
		})
		return nil
	})
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, err
}

// Folders lists the distinct directories entries live in, so a form can show what conventions this
// store already follows instead of asking the user to remember them.
func Folders() []string {
	entries, err := Entries()
	if err != nil && len(entries) == 0 {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, e := range entries {
		if e.Folder == "" || seen[e.Folder] {
			continue
		}
		seen[e.Folder] = true
		out = append(out, e.Folder)
	}
	sort.Strings(out)
	return out
}

// Exists reports whether an entry is already there, so a generated secret never silently replaces
// one that is still in use somewhere.
func Exists(name string) bool {
	_, err := os.Stat(filepath.Join(dir(), filepath.FromSlash(name)+".gpg"))
	return err == nil
}

// ValidName rejects a path that would escape the store or produce an unreachable entry.
//
// `pass` joins the name onto the store directory without much argument, so "../../.ssh/id_ed25519"
// is a file it will cheerfully encrypt over. The check belongs here, at the one place a name turns
// into a path, rather than in whichever form happens to be collecting it.
func ValidName(name string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return fmt.Errorf("empty entry name")
	}
	if strings.HasPrefix(name, "/") {
		return fmt.Errorf("the name is a path inside the store, not on disk — drop the leading slash")
	}
	for _, seg := range strings.Split(name, "/") {
		if seg == "" {
			return fmt.Errorf("empty segment in path %q", name)
		}
		if seg == "." || seg == ".." {
			return fmt.Errorf("%q leads outside the store", name)
		}
	}
	return nil
}

// Insert writes a freshly generated secret into the store. It refuses to overwrite.
func Insert(name, secret string, meta map[string]string) error {
	if err := ValidName(name); err != nil {
		return err
	}
	if Exists(name) {
		return fmt.Errorf("entry %q already exists — pick another name", name)
	}
	return write(name, func(w io.Writer) error {
		_, err := io.WriteString(w, secret)
		return err
	}, meta)
}

// InsertSecret writes a secret held in locked memory. It refuses to overwrite.
//
// This is the path a password the user typed takes: from the mlocked buffer, through a pipe, into
// gpg. See write below for why that pipe is built by hand.
func InsertSecret(name string, secret *sys.Secret, meta map[string]string) error {
	if err := ValidName(name); err != nil {
		return err
	}
	if Exists(name) {
		return fmt.Errorf("entry %q already exists — pick another name", name)
	}
	return write(name, func(w io.Writer) error {
		_, err := secret.WriteTo(w)
		return err
	}, meta)
}

// Replace overwrites an existing entry. It refuses to CREATE one, which is the mirror of Insert:
// between them, no single call can both fail to find what you meant and silently do the other thing.
func Replace(name string, secret *sys.Secret, meta map[string]string) error {
	if err := ValidName(name); err != nil {
		return err
	}
	if !Exists(name) {
		return fmt.Errorf("no entry %q", name)
	}
	return write(name, func(w io.Writer) error {
		_, err := secret.WriteTo(w)
		return err
	}, meta)
}

// write runs `pass insert --multiline` and feeds it the body through a pipe of our own.
//
// The stdin is an *os.File and that is the entire reason this is not three lines. Handed any other
// reader, os/exec starts a goroutine that copies through a 32 KB buffer on the Go heap — a copy of
// the password that cannot be wiped and that the collector is free to duplicate while compacting.
// An *os.File is passed to the child as a file descriptor, so the bytes travel from the locked
// buffer into the kernel's pipe and touch nothing in between.
//
// --force is always given. Not to overwrite blindly — Insert and Replace have already decided that
// question in Go, where the answer can be reported properly — but because without it `pass` asks
// for confirmation on stdin, and the "y" it is waiting for would be read out of the password.
func write(name string, secret func(io.Writer) error, meta map[string]string) error {
	pr, pw, err := os.Pipe()
	if err != nil {
		return fmt.Errorf("pipe: %w", err)
	}
	cmd := exec.Command("pass", "insert", "--multiline", "--force", name)
	cmd.Stdin = pr
	errb := &strings.Builder{}
	cmd.Stderr = errb
	cmd.Stdout = nil

	if err := cmd.Start(); err != nil {
		_ = pr.Close()
		_ = pw.Close()
		return fmt.Errorf("pass insert: %w", err)
	}
	// The child holds its own descriptor now; ours must go, or the read end never sees EOF.
	_ = pr.Close()

	werr := writeBody(pw, secret, meta)
	_ = pw.Close()

	if err := cmd.Wait(); err != nil {
		msg := strings.TrimSpace(errb.String())
		if msg == "" {
			msg = err.Error()
		}
		return fmt.Errorf("pass insert: %s", msg)
	}
	return werr
}

// writeBody lays out the entry: the password on the first line, metadata below it. That order is
// the convention the rest of the pass ecosystem reads — `pass show -c` copies line one and nothing
// else, so anything written above the password would be copied instead of it.
func writeBody(w io.Writer, secret func(io.Writer) error, meta map[string]string) error {
	if err := secret(w); err != nil {
		return err
	}
	if _, err := io.WriteString(w, "\n"); err != nil {
		return err
	}
	// Deterministic order, so the same inputs produce the same file and a git-backed store shows
	// meaningful diffs instead of reordered noise.
	keys := make([]string, 0, len(meta))
	for k := range meta {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		v := strings.TrimSpace(meta[k])
		if v == "" {
			continue
		}
		// A newline in a value would forge an extra field; a field is one line by definition.
		v = strings.ReplaceAll(v, "\n", " ")
		if _, err := fmt.Fprintf(w, "%s: %s\n", k, v); err != nil {
			return err
		}
	}
	return nil
}

// Remove deletes an entry. Nothing here asks whether you are sure — the view does that, where the
// name being deleted is on screen.
func Remove(name string) error {
	if err := ValidName(name); err != nil {
		return err
	}
	if !Exists(name) {
		return fmt.Errorf("no entry %q", name)
	}
	res, err := sys.Run("pass", "rm", "--force", name)
	if err != nil {
		return err
	}
	if !res.OK() {
		return fmt.Errorf("pass rm: %s", firstLine(res.Stderr, "delete failed"))
	}
	return nil
}

// Move renames an entry, folders included — moving `websites/x/me` to `old/x/me` is how an account
// gets retired without losing what its password was.
func Move(from, to string) error {
	if err := ValidName(from); err != nil {
		return err
	}
	if err := ValidName(to); err != nil {
		return err
	}
	if from == to {
		return nil
	}
	if !Exists(from) {
		return fmt.Errorf("no entry %q", from)
	}
	if Exists(to) {
		return fmt.Errorf("entry %q already exists", to)
	}
	res, err := sys.Run("pass", "mv", from, to)
	if err != nil {
		return err
	}
	if !res.OK() {
		return fmt.Errorf("pass mv: %s", firstLine(res.Stderr, "move failed"))
	}
	return nil
}

// CopyCmd builds the command that puts an entry's password on the clipboard.
//
// `pass show --clip` copies the first line and wipes the clipboard again after
// PASSWORD_STORE_CLIP_TIME seconds (45 by default). The password is decrypted by gpg and handed to
// the clipboard helper; keyforge never sees it, which is strictly better than reading it here and
// copying it ourselves, and is why there is no "reveal" beside this.
//
// It is returned as a command rather than run, because gpg may need to ask for the passphrase and
// pinentry-curses wants the real terminal. The caller hands this to tea.ExecProcess.
func CopyCmd(name string) *exec.Cmd {
	return sys.Interactive("pass", "show", "--clip", name)
}

// Reveal decrypts an entry and returns its password in locked memory.
//
// This is the one call in the package that hands the password back, and it is built so that doing
// so costs as little as it can. `pass show` writes into a pipe this package owns, and the bytes are
// read straight into an mlocked buffer: no heap string, nothing for the collector to duplicate,
// nothing that cannot be wiped. The caller must Close the result.
//
// It exists because a password you can only copy is a password you cannot read off the screen to
// type into a phone, and that turned out to be a real thing people need. It is still the weaker
// path — the value ends up on a screen — which is why the view puts it behind its own key, hides it
// again on a timer, and never turns it on by itself.
func Reveal(name string) (*sys.Secret, error) {
	if err := ValidName(name); err != nil {
		return nil, err
	}
	pr, pw, err := os.Pipe()
	if err != nil {
		return nil, fmt.Errorf("pipe: %w", err)
	}
	cmd := exec.Command("pass", "show", name)
	cmd.Stdout = pw
	errb := &strings.Builder{}
	cmd.Stderr = errb
	// No stdin, for the same reason Run has none: with the agent locked, pinentry must fail rather
	// than block behind a TUI that has already painted over its question.
	cmd.Stdin = nil

	if err := cmd.Start(); err != nil {
		_ = pr.Close()
		_ = pw.Close()
		return nil, fmt.Errorf("pass show: %w", err)
	}
	// Our copy of the write end must go, or the read below never sees EOF.
	_ = pw.Close()

	// 4 KB is far more than any password and still one page of locked memory.
	sec, err := sys.NewSecret(4096)
	if err != nil {
		_ = pr.Close()
		_ = cmd.Wait()
		return nil, err
	}
	_, rerr := sec.ReadFrom(pr)
	_ = pr.Close()

	if err := cmd.Wait(); err != nil {
		sec.Close()
		return nil, fmt.Errorf("%s", firstLine(errb.String(), "gpg did not unlock the entry"))
	}
	if rerr != nil {
		sec.Close()
		return nil, rerr
	}
	// Only line one is the password; the metadata below it is dropped inside the locked buffer.
	sec.TruncateAt('\n')
	return sec, nil
}

// Fields returns an entry's metadata — and deliberately not its password.
//
// The whole record has to be decrypted to read any of it, so the first line necessarily passes
// through this process; it is dropped here and never returned, so no caller can render it by
// accident. Nothing above needs the password: copying goes through CopyCmd, which never comes back
// here at all.
func Fields(name string) (map[string]string, error) {
	if err := ValidName(name); err != nil {
		return nil, err
	}
	// No stdin, by Run's design: if the gpg agent is locked, pinentry fails immediately instead of
	// hanging behind a TUI that has already painted over its question.
	res, err := sys.Run("pass", "show", name)
	if err != nil {
		return nil, err
	}
	if !res.OK() {
		return nil, fmt.Errorf("%s", firstLine(res.Stderr, "gpg did not unlock the entry"))
	}
	out := map[string]string{}
	lines := strings.Split(res.Stdout, "\n")
	for _, l := range lines[min(1, len(lines)):] {
		k, v, ok := strings.Cut(l, ":")
		if !ok {
			continue
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		if k != "" && v != "" {
			out[k] = v
		}
	}
	return out, nil
}

// SuggestName proposes a store path for a secret belonging to a key or host, following the
// convention most stores already use: a directory per kind, then the thing itself.
func SuggestName(kind, subject string) string {
	subject = strings.TrimSuffix(subject, ".pub")
	subject = strings.ReplaceAll(subject, " ", "-")
	return path.Join(kind, subject)
}

// firstLine reduces a tool's complaint to the part worth showing on a one-line status bar.
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
