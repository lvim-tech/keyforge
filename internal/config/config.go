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
// For those who prefer convenience over that margin there is ValuesFrom: a `pass` entry holding the
// values, encrypted with the GPG key. It is opt-in, it is off by default, and its limit is the same
// one that applies to every local store — root, while the agent is unlocked, reads it.
package config

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Sheet is the persisted half of the printing rule.
type Sheet struct {
	Strip      string   `json:"strip"`       // characters scattered as noise
	StripCount int      `json:"strip_count"` // how many to scatter
	Markers    []string `json:"markers"`     // characters that stand for something memorised
	// ValuesFrom names a `pass` entry holding "marker=value" lines. Empty — the default — means the
	// values are asked for at print time and kept only in memory.
	ValuesFrom string `json:"values_from,omitempty"`
}

// Config is everything keyforge remembers.
type Config struct {
	PasswordLength int      `json:"password_length"`
	PhraseWords    int      `json:"phrase_words"`
	Separator      string   `json:"separator"`
	KDFRounds      int      `json:"kdf_rounds"` // bcrypt-KDF rounds for new SSH keys
	CertPaths      []string `json:"cert_paths,omitempty"`
	Sheet          Sheet    `json:"sheet"`
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
var (
	buildStrip      = ""
	buildStripCount = ""
	buildMarkers    = ""
)

// Default is what a machine with no config behaves like, after applying any build-time structure.
func Default() Config {
	c := Config{
		PasswordLength: 20,
		PhraseWords:    5,
		Separator:      "-",
		KDFRounds:      100,
	}
	c.Sheet.Strip = buildStrip
	if n, err := strconv.Atoi(strings.TrimSpace(buildStripCount)); err == nil && n >= 0 {
		c.Sheet.StripCount = n
	}
	c.Sheet.SetMarkers(buildMarkers)
	return c
}

// BuiltIn reports whether this binary carries a structure compiled into it, so the interface can
// say so rather than leaving the user wondering where the defaults came from.
func BuiltIn() bool {
	return buildStrip != "" || buildMarkers != ""
}

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

// Save writes the config with 0600 permissions.
//
// The values behind the markers are not part of the Config type at all, so there is no path by which
// a moment's carelessness could serialise them. That is deliberate: a comment saying "do not write
// the secret here" is a request, while a struct that cannot hold the secret is a guarantee.
func Save(c Config) error {
	p := Path()
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(p, append(b, '\n'), 0o600)
}

// MarkerRunes returns the configured markers as runes, ignoring malformed entries.
func (s Sheet) MarkerRunes() []rune {
	var out []rune
	for _, m := range s.Markers {
		r := []rune(m)
		if len(r) == 1 {
			out = append(out, r[0])
		}
	}
	return out
}

// SetMarkers stores marker characters from a comma-free string such as "zj".
func (s *Sheet) SetMarkers(chars string) {
	s.Markers = nil
	seen := map[rune]bool{}
	for _, r := range chars {
		if r == ' ' || r == ',' || seen[r] {
			continue
		}
		seen[r] = true
		s.Markers = append(s.Markers, string(r))
	}
}

// ParseValues reads "marker=value" pairs, the form used both by the print prompt and by the
// optional `pass` entry. Whitespace around a value is preserved — a trailing space is a legitimate,
// if unwise, part of a secret, and silently trimming it would produce a password that does not work.
func ParseValues(text string) (map[rune]string, error) {
	out := map[rune]string{}
	for _, line := range strings.FieldsFunc(text, func(r rune) bool { return r == '\n' || r == ',' }) {
		line = strings.TrimSpace(line)
		if line == "" {
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
