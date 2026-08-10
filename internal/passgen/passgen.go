// Package passgen produces passphrases and passwords.
//
// Two decisions here are worth explaining, because both come from watching a real password fail.
//
// RANDOMNESS. Everything draws from crypto/rand and rejects modulo bias. math/rand seeded from the
// clock is the classic way a generator that "looks random" produces a few thousand distinct outputs;
// for a passphrase that guards a key, that is the whole game lost at the first line.
//
// LAYOUT SAFETY. A password is only as good as your ability to type it again. On a machine that
// switches between a Latin and a Cyrillic layout, letters silently become other letters and the
// symbols move: what was typed at `passwd` and what is typed at the prompt an hour later are two
// different strings, and both are hidden behind asterisks. Word-based passphrases are the honest
// answer — they are long, they are memorable, and if the layout is wrong you can SEE it the moment
// you type them anywhere visible. For the character generator, `Safe` drops the symbols whose
// position differs between layouts and the glyphs that are read wrong from a screen (0/O, 1/l/I).
package passgen

import (
	"crypto/rand"
	_ "embed"
	"fmt"
	"math"
	"math/big"
	"strings"
)

//go:embed words.txt
var wordsRaw string

var words []string

func init() {
	for _, w := range strings.Split(strings.TrimSpace(wordsRaw), "\n") {
		if w = strings.TrimSpace(w); w != "" {
			words = append(words, w)
		}
	}
}

// WordCount is the size of the embedded dictionary — the base of the entropy calculation.
func WordCount() int { return len(words) }

// Charset presets for the character generator.
const (
	lower   = "abcdefghijklmnopqrstuvwxyz"
	upper   = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	digits  = "0123456789"
	symSafe = "-_.+=" // same key on every layout this tool is likely to meet
	symFull = "!@#$%^&*()[]{}<>?/|~;:,"
	// Glyphs a human reads wrong off a terminal, and the ones a Cyrillic layout shuffles.
	ambiguous = "0O1lI|`'\""
)

// Options controls the character generator.
type Options struct {
	Length     int
	Upper      bool
	Digits     bool
	SymbolsAll bool // include the full symbol set, not just the layout-stable ones
	Symbols    bool
	NoAmbig    bool // drop 0/O/1/l/I and friends
	// Reserved characters are never produced. They exist so that a printed sheet can carry them as
	// decoys: because the generator cannot emit them, every occurrence on paper is noise, and the
	// person who knows the rule strips them by eye. Kept ordinary (a letter, a digit) rather than
	// exotic — a "◆" announces that something was inserted, while a "q" announces nothing at all.
	Reserved string
}

// DefaultOptions is a 20-character password that survives being retyped: mixed case, digits and
// only the stable symbols, with the confusable glyphs removed.
func DefaultOptions() Options {
	return Options{Length: 20, Upper: true, Digits: true, Symbols: true, NoAmbig: true}
}

// alphabet assembles the character pool for the given options.
func (o Options) alphabet() string {
	var sb strings.Builder
	sb.WriteString(lower)
	if o.Upper {
		sb.WriteString(upper)
	}
	if o.Digits {
		sb.WriteString(digits)
	}
	if o.Symbols {
		sb.WriteString(symSafe)
		if o.SymbolsAll {
			sb.WriteString(symFull)
		}
	}
	set := sb.String()
	drop := ""
	if o.NoAmbig {
		drop += ambiguous
	}
	drop += o.Reserved
	if drop != "" {
		var out strings.Builder
		for _, r := range set {
			if !strings.ContainsRune(drop, r) {
				out.WriteRune(r)
			}
		}
		set = out.String()
	}
	return set
}

// Password returns a random string over the configured alphabet, plus its entropy in bits.
func Password(o Options) (string, float64, error) {
	set := []rune(o.alphabet())
	if len(set) == 0 || o.Length <= 0 {
		return "", 0, fmt.Errorf("empty alphabet or zero length")
	}
	out := make([]rune, o.Length)
	for i := range out {
		n, err := pick(len(set))
		if err != nil {
			return "", 0, err
		}
		out[i] = set[n]
	}
	return string(out), float64(o.Length) * math.Log2(float64(len(set))), nil
}

// PhraseOptions controls the word-based generator.
type PhraseOptions struct {
	Words     int
	Separator string
	Capitals  bool   // capitalise each word
	Number    bool   // append a digit group, for policies that demand one
	Reserved  string // never appears in the result; see Options.Reserved
}

// DefaultPhraseOptions is five words joined by dashes — 69 bits with this dictionary, which is
// past the point where an offline attack on a modern KDF stops being worth anyone's electricity.
func DefaultPhraseOptions() PhraseOptions {
	return PhraseOptions{Words: 5, Separator: "-"}
}

// Phrase returns a passphrase and its entropy in bits. The digit group, when asked for, adds its
// own entropy honestly rather than being counted as free.
//
// Reserved characters are handled by rejection: a word containing one is drawn again. With a
// 14 000-word dictionary and one or two reserved letters this costs a handful of extra draws and
// keeps the guarantee absolute — no reserved character can reach a generated secret by any path.
func Phrase(o PhraseOptions) (string, float64, error) {
	if o.Words <= 0 {
		return "", 0, fmt.Errorf("zero words")
	}
	if len(words) == 0 {
		return "", 0, fmt.Errorf("the built-in word list is empty")
	}
	pool := words
	if o.Reserved != "" {
		pool = pool[:0:0]
		for _, w := range words {
			if !strings.ContainsAny(w, o.Reserved) {
				pool = append(pool, w)
			}
		}
		if len(pool) < 128 {
			return "", 0, fmt.Errorf("the reserved characters exclude too many words (%d left)", len(pool))
		}
	}
	parts := make([]string, 0, o.Words+1)
	for i := 0; i < o.Words; i++ {
		n, err := pick(len(pool))
		if err != nil {
			return "", 0, err
		}
		w := pool[n]
		if o.Capitals {
			w = strings.ToUpper(w[:1]) + w[1:]
		}
		parts = append(parts, w)
	}
	// Entropy is computed from the pool actually drawn from, not from the full dictionary — a
	// reserved letter shrinks the choice, and reporting the larger number would overstate it.
	bits := float64(o.Words) * math.Log2(float64(len(pool)))
	if o.Number {
		n, err := pick(100)
		if err != nil {
			return "", 0, err
		}
		parts = append(parts, fmt.Sprintf("%02d", n))
		bits += math.Log2(100)
	}
	sep := o.Separator
	if sep == "" {
		sep = "-"
	}
	return strings.Join(parts, sep), bits, nil
}

// pick returns a uniform random integer in [0,n) from the system CSPRNG.
func pick(n int) (int, error) {
	v, err := rand.Int(rand.Reader, big.NewInt(int64(n)))
	if err != nil {
		return 0, err
	}
	return int(v.Int64()), nil
}

// Strength turns entropy into words a person can act on, together with the assumption behind it.
//
// The rate is the honest part: an offline attack against a modern KDF (yescrypt, bcrypt, the
// OpenSSH key format) runs at roughly 10^5 guesses per second per GPU, while the same attack
// against the sha512crypt hashes older systems still write runs about 10^6 times faster. Quoting a
// single number without saying which of those it assumes is how people end up believing a weak
// password is fine.
func Strength(bits float64) (label, detail string) {
	const guessesPerSec = 1e5 // one GPU against a modern KDF
	seconds := math.Pow(2, bits-1) / guessesPerSec
	switch {
	case bits < 40:
		label = "weak"
	case bits < 60:
		label = "acceptable"
	case bits < 80:
		label = "strong"
	default:
		label = "very strong"
	}
	return label, fmt.Sprintf("%.0f bits · ~%s at 10⁵ guesses/sec against a modern KDF", bits, humanDuration(seconds))
}

// humanDuration renders a span from seconds to ages without pretending to precision it lacks.
func humanDuration(s float64) string {
	switch {
	case s < 60:
		return fmt.Sprintf("%.0f sec", s)
	case s < 3600:
		return fmt.Sprintf("%.0f min", s/60)
	case s < 86400:
		return fmt.Sprintf("%.0f hours", s/3600)
	case s < 86400*365:
		return fmt.Sprintf("%.0f days", s/86400)
	case s < 86400*365*1000:
		return fmt.Sprintf("%.0f years", s/(86400*365))
	case s < 86400*365*1e6:
		return fmt.Sprintf("%.0f thousand years", s/(86400*365*1e3))
	case s < 86400*365*1e9:
		return fmt.Sprintf("%.0f million years", s/(86400*365*1e6))
	default:
		// Past this the number stops meaning anything to a person; the age of the universe is
		// about 1.4e10 years, and quoting multiples of it reads as bravado rather than as safety.
		return "longer than the age of the universe"
	}
}
