// Package config persists keyforge's settings.
//
// WHAT IS WRITTEN AND WHAT IS NOT is the whole design of this file.
//
// The sheet rule has two halves that look alike and are not. The STRUCTURE — which characters are
// noise, how many get scattered, which characters act as markers — is a habit: knowing it tells an
// attacker that a scheme exists and lets him strip the noise, but the page still refuses to give up
// the password. The VALUES behind the markers are the secret itself: the thing that was deliberately
// never written on the sheet, so that holding the paper is not enough.
//
// Structure is therefore saved and values never are. A config file is readable by anyone who reaches
// the home directory, and on a machine that has been rooted once, "readable by anyone who reaches
// the home directory" means "already read". Retyping the whole rule every time would invite a typo,
// and a typo in the rule produces a sheet that cannot be decoded afterwards — so the compromise is
// to retype only the part that is actually a secret.
//
// The rule now lives entirely in `pass`, encrypted with the GPG key, under a name the user
// chooses. Its limit is the one that applies to every local store: root, while the agent is
// unlocked, reads it. That is not a weakness of this arrangement but of the machine, and on a
// machine in that state the passwords themselves are already readable.
package config

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
)

// Sheet is what the config keeps about the printing rule, which is now only where to find
// it.
//
// The rule itself — noise characters, how many, markers, what each marker stands for — lives
// encrypted in a `pass` entry. It used to live here in plain text on the reasoning that
// knowing the structure does not open a password, and that reasoning was wrong in the one
// case the sheet exists for: once the paper is in somebody's hands, "delete every q and 7"
// is the key to reading it. The paper is the part of this system designed to leave the
// machine, so the machine must not also hold its legend.
//
// The name is chosen by the user and says nothing about what is inside. This file therefore
// reveals that keyforge reads something from `pass`, and not that a masking scheme exists.
type Sheet struct {
	// RuleFrom names the `pass` entry holding the rule. Empty means there is no rule, and
	// nothing anywhere says so.
	RuleFrom string `json:"rule_from,omitempty"`

	// CacheMinutes is how long keyforge keeps the rule after reading it.
	//
	// This is keyforge's own cache, not the agent's, and the difference matters: while it
	// holds, the decrypted rule is in this process's memory whether or not gpg-agent has
	// forgotten anything. That is why the interface says so in red while it lasts, and why
	// there is a key to end it early. 0 means do not keep it at all — every generation and
	// every print asks again.
	CacheMinutes int `json:"cache_minutes"`
}

// Lock is the idle screen lock.
//
// NOTHING SECRET IS STORED HERE, and that is the point of the design rather than an accident of it.
// keyforge holds no password of its own to check against: the lock is opened by proving you can use
// the GPG key that `pass` encrypts to, which gpg asks for through pinentry and keyforge never sees.
// So there is no hash in this file, no salt, no parameters to age badly, and no second secret to
// remember that would protect less than the one you already have.
//
// ClearAgent is what turns the lock from a curtain into a lock. Without it, gpg signs straight from
// the agent's cache and the unlock prompt never appears — the lock would open on an empty keypress
// for exactly as long as the cache lasts, which is exactly the window it exists to cover. With it,
// locking forgets the passphrase, so unlocking must ask. The cost is real and is why it is a
// setting: the agent is shared, so this also makes your other terminals and your signed commits ask
// again.
type Lock struct {
	// IdleMinutes is how long keyforge may sit untouched before it locks. 0 disables the lock.
	IdleMinutes int `json:"idle_minutes"`
	// ClearAgent drops the gpg-agent passphrase cache when locking.
	ClearAgent bool `json:"clear_agent"`
	// AtStart locks before the first screen is drawn, so keyforge opens closed.
	//
	// What it is worth depends entirely on ClearAgent, and the pairing is the whole of the
	// setting. With the agent still holding the passphrase, the unlock opens without asking
	// anything — the store is already open, and keyforge would only be pretending otherwise.
	// With ClearAgent it genuinely asks, at the price of shutting the store for everything
	// else on the machine at the moment you open a program to look at it.
	AtStart bool `json:"at_start"`

	// Key locks on demand. Empty means there is no such key and only the idle timer locks.
	//
	// Configurable because a terminal is already full of bindings that are somebody else's: the
	// obvious choice, ctrl+l, is a tmux window binding on this machine and a redraw everywhere else.
	// Whatever is chosen here is claimed by the shell BEFORE any tab sees it, so picking a key a tab
	// needs takes it away from that tab.
	Key string `json:"key"`
}

// Agent is keyforge's view of how long the REAL master password stays active.
//
// The passphrase on the store's GPG key is what actually holds everything in `pass` shut, and how
// long it stays entered is decided by gpg-agent, not by keyforge. These two values are written into
// ~/.gnupg/gpg-agent.conf rather than kept here, because a setting that keyforge remembered but
// gpg-agent did not read would describe a protection that is not in force. Zero means "leave
// gpg-agent's own configuration alone".
type Agent struct {
	DefaultCacheTTL int `json:"default_cache_ttl"` // seconds; gpg's own default is 600
	MaxCacheTTL     int `json:"max_cache_ttl"`     // seconds; gpg's own default is 7200
}

// Config is everything keyforge remembers.
type Config struct {
	PasswordLength int    `json:"password_length"`
	PhraseWords    int    `json:"phrase_words"`
	Separator      string `json:"separator"`
	KDFRounds      int    `json:"kdf_rounds"` // bcrypt-KDF rounds for new SSH keys
	// Ambiguous is the character set the generator's "no ambiguous" switch removes. Empty
	// means the built-in one, which is what the Generator names on screen. Configurable
	// because which glyphs are unreadable depends on the font in use, and which are
	// unstable depends on the keyboard layouts this particular reader switches between —
	// the failure that lost the old store's passphrase.
	Ambiguous string   `json:"ambiguous,omitempty"`
	CertPaths []string `json:"cert_paths,omitempty"`
	Sheet     Sheet    `json:"sheet"`
	Lock      Lock     `json:"lock"`
	Agent     Agent    `json:"agent"`
}

// Build-time defaults. Set with -ldflags so a personal build already knows the sheet STRUCTURE
// without any file on disk:
//
//	go build -ldflags "-X github.com/lvim-tech/keyforge/internal/config.buildStrip=q7 \
//	                   -X github.com/lvim-tech/keyforge/internal/config.buildStripCount=2 \
//	                   -X github.com/lvim-tech/keyforge/internal/config.buildMarkers=z"
//
// THE VALUES BEHIND THE MARKERS MUST NEVER BE BAKED IN. A linker-set string sits in the binary as
// plaintext and `strings` finds it in one command; worse, Go records the entire -ldflags line in the
// build info, so the flag itself is readable too. Encrypting it changes nothing, because the key
// would have to be in the binary as well. A program that knows the value without asking CONTAINS
// the value — that is why only structure is accepted here.
var buildRuleFrom = ""

// Default is what a machine with no config behaves like, after applying any build-time structure.
func Default() Config {
	c := Config{
		PasswordLength: 20,
		PhraseWords:    5,
		Separator:      "-",
		KDFRounds:      100,
	}
	// The lock is off until asked for. A tool that starts demanding a passphrase on its own, on a
	// machine where nothing has been decided yet, teaches people to turn it off rather than to use it.
	c.Lock = Lock{IdleMinutes: 0, ClearAgent: true, Key: "ctrl+x", AtStart: false}
	c.Sheet.CacheMinutes = 60
	// A build-time rule would have to carry its marker VALUES to be of any use, and those
	// must never be in the binary: a linker-set string sits there in plain text and `strings`
	// finds it in one command. What remains bakeable is a pointer to the entry that holds it.
	if buildRuleFrom != "" {
		c.Sheet.RuleFrom = buildRuleFrom
	}
	return c
}

// BuiltIn reports whether this binary carries a structure compiled into it, so the interface can
// say so rather than leaving the user wondering where the defaults came from.
func BuiltIn() bool { return buildRuleFrom != "" }

// Path is the config file location, honouring XDG_CONFIG_HOME.
func Path() string {
	if d := os.Getenv("XDG_CONFIG_HOME"); d != "" {
		return filepath.Join(d, "keyforge", "config.json")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "keyforge.json"
	}
	return filepath.Join(home, ".config", "keyforge", "config.json")
}

// Load reads the config, falling back to defaults for anything missing. A broken file is reported
// rather than silently replaced: settings that quietly reset are how a sheet gets printed under a
// rule the user no longer thinks is in force.
func Load() (Config, error) {
	c := Default()
	b, err := os.ReadFile(Path())
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return c, nil
		}
		return c, err
	}
	if err := json.Unmarshal(b, &c); err != nil {
		return Default(), err
	}
	if c.PasswordLength <= 0 {
		c.PasswordLength = 20
	}
	if c.PhraseWords <= 0 {
		c.PhraseWords = 5
	}
	if c.KDFRounds <= 0 {
		c.KDFRounds = 100
	}
	return c, nil
}

// Save writes the config, keeping anything in the file this build does not know about.
//
// A plain marshal of the struct would be shorter and would silently delete every key a newer
// keyforge — or the user's own hand — had put there. The same rule the installer follows for
// gpg-agent.conf applies to our own file: this is somebody's configuration, and a tool that
// rewrites it wholesale to change one number will eventually take something with it.
//
// The merge is by top-level key, which is as deep as it needs to be: every section here is
// owned entirely by one part of the program, so an unknown SECTION is preserved whole and a
// known one is replaced whole.
//
// The values behind the markers are not part of the Config type at all, so there is no path by which
// a moment's carelessness could serialise them. That is deliberate: a comment saying "do not write
// the secret here" is a request, while a struct that cannot hold the secret is a guarantee.
func Save(c Config) error {
	p := Path()
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}

	ours, err := json.Marshal(c)
	if err != nil {
		return err
	}
	merged := map[string]json.RawMessage{}
	if existing, err := os.ReadFile(p); err == nil {
		// A file we cannot parse is not a reason to lose it. Better to write ours alone than
		// to refuse to save, but the old text is left in place beside it.
		if err := json.Unmarshal(existing, &merged); err != nil {
			_ = os.WriteFile(p+".unparsed", existing, 0o600)
			merged = map[string]json.RawMessage{}
		}
	}
	var mine map[string]json.RawMessage
	if err := json.Unmarshal(ours, &mine); err != nil {
		return err
	}
	for k, v := range mine {
		merged[k] = v
	}

	b, err := json.MarshalIndent(merged, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(p, append(b, '\n'), 0o600)
}

// Update is the ONLY safe way to change one part of the config.
//
// Save takes a whole Config, and every caller had its own copy taken at startup. Two savers in
// one session therefore reverted each other: storing the rule in Print wrote Print's stale
// `lock` and `agent` sections over whatever Settings had just saved, and a later save from
// Settings wrote its stale `sheet` section — with an empty rule_from — over the pointer to the
// rule entry that had just been created. That pointer is a random name chosen so nobody can
// find the entry; losing it orphans the rule and the sheets printed under it, silently.
//
// So: re-read from disk, apply ONLY what the caller means to change, write back. It also covers
// the case Save alone never could — a second keyforge, or the user's own editor, having touched
// the file since this process started.
func Update(apply func(*Config)) (Config, error) {
	c, err := Load()
	if err != nil {
		// A file we cannot parse is reported rather than overwritten from a default: the caller
		// deciding to write anyway would erase settings the user can still fix by hand.
		return c, err
	}
	apply(&c)
	if err := Save(c); err != nil {
		return c, err
	}
	return c, nil
}

// ParseValues reads "marker=value" pairs, the form used both by the print prompt and by the
// optional `pass` entry.
//
// WHITESPACE AFTER THE `=` IS KEPT. A trailing space is a legitimate, if unwise, part of a
// secret, and trimming it silently produces a password that does not work — so only the key side
// is trimmed. The comment used to promise this while `TrimSpace` on the whole line took the
// value's trailing space away, which is the worst kind of documentation.
//
// A comma and a newline SEPARATE pairs, so neither can appear in a value. ValidateRule refuses
// them for the same reason it refuses the field separator: a value that cannot be re-entered is
// a value that will one day not be.
func ParseValues(text string) (map[rune]string, error) {
	out := map[rune]string{}
	for _, line := range strings.FieldsFunc(text, func(r rune) bool { return r == '\n' || r == ',' }) {
		if strings.TrimSpace(line) == "" {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		k = strings.TrimSpace(k)
		if !ok || len([]rune(k)) != 1 || v == "" {
			return nil, errors.New("write marker=value, e.g. z=WHATEVER-YOU-REMEMBER")
		}
		out[[]rune(k)[0]] = v
	}
	return out, nil
}
