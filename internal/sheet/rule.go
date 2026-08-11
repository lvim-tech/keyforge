package sheet

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

// Rule is the whole of the printing scheme: which characters are noise, how many are
// scattered, which characters are markers, and what each marker stands for.
//
// ALL OF IT TOGETHER, and that is the change from how this used to be kept. The structure
// once lived in the config in plain text while only the values were withheld, on the
// reasoning that knowing the structure does not open a password. That reasoning holds only
// while the sheet is out of reach. Once the paper is in somebody's hands, the structure IS
// the key to it: "delete every q and 7" turns a page of noise back into the password. The
// paper is the one part of this system designed to leave the machine, so the machine must
// not also hold its legend.
//
// So the rule goes into `pass`, encrypted like everything else there, under a name the user
// chooses — one that says nothing about what is inside. The config keeps only that name.
type Rule struct {
	Strip   string
	StripN  int
	Markers map[rune]string
}

// Mask converts to the form the composing code uses.
func (r Rule) Mask() Mask {
	m := Mask{Strip: r.Strip, StripN: r.StripN}
	if len(r.Markers) > 0 {
		m.Expand = map[rune]string{}
		for k, v := range r.Markers {
			m.Expand[k] = v
		}
	}
	return m
}

// Empty reports a rule that would do nothing.
func (r Rule) Empty() bool { return r.StripN <= 0 && len(r.Markers) == 0 }

// sep separates the fields of the stored rule.
//
// Fixed, not generated at build time. A per-build separator was considered and rejected: it
// would be found in the binary by `strings` in a second, so it buys nothing against anyone
// who already has the machine — and a rebuild with a different one would leave the stored
// rule unreadable, silently and completely. Obscurity that a rebuild can destroy is not
// worth having.
//
// A colon is safe by construction rather than by hope: ValidateRule refuses it in every
// field, so it cannot appear in the data it separates.
const sep = ":"

// Encode renders the rule as the body of a `pass` entry.
//
// ONE LINE, UNLABELLED, and that is the point. The first version wrote "keyforge" on the
// first line and then "strip: q7", "marker-z: Qx9" — an entry that announced exactly what it
// was to anyone who opened it. A password store is full of one-line entries that look like
// this; the rule should be one more of them.
//
//	q7:3:z:Qx9        noise, how many, then marker and what it stands for, in pairs
func (r Rule) Encode() string {
	parts := []string{r.Strip, fmt.Sprintf("%d", r.StripN)}
	keys := make([]rune, 0, len(r.Markers))
	for k := range r.Markers {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
	for _, k := range keys {
		parts = append(parts, string(k), r.Markers[k])
	}
	return strings.Join(parts, sep) + "\n"
}

// DecodeRule reads back what Encode wrote.
//
// A line it cannot make sense of yields the empty rule rather than an error, for the same
// reason nothing else here reports: a complaint about a malformed rule is a statement that a
// rule was expected.
// DecodeRuleStrict is DecodeRule for the caller that already KNOWS a rule was expected.
//
// DecodeRule answers the empty rule for anything it cannot parse, and its reason is sound where
// it applies: a complaint about a malformed rule is a statement that a rule exists. That
// justification does not survive the move into ruleCache.get, where `configured()` is already
// true — there the silence turns "the rule cannot be read" into "there is no rule", and
// generation carries on with no reserved set while the user believes the rule is in force. The
// bool says which of the two it was; the lenient form stays for every display path.
func DecodeRuleStrict(body string) (Rule, bool) {
	if strings.TrimSpace(body) == "" {
		return Rule{}, false
	}
	r := DecodeRule(body)
	if r.Empty() && r.Strip == "" {
		return Rule{}, false
	}
	return r, true
}

func DecodeRule(body string) Rule {
	line := strings.TrimSpace(body)
	if i := strings.IndexAny(line, "\r\n"); i >= 0 {
		line = line[:i]
	}
	parts := strings.Split(line, sep)
	if len(parts) < 2 {
		return Rule{}
	}
	r := Rule{Strip: parts[0]}
	if _, err := fmt.Sscanf(parts[1], "%d", &r.StripN); err != nil {
		return Rule{}
	}
	for i := 2; i+1 < len(parts); i += 2 {
		k := []rune(parts[i])
		if len(k) != 1 || parts[i+1] == "" {
			continue
		}
		if r.Markers == nil {
			r.Markers = map[rune]string{}
		}
		r.Markers[k[0]] = parts[i+1]
	}
	return r
}

// GenerateName invents a name for the entry that will hold the rule.
//
// Random per installation, not derived from anything in the binary: a name every keyforge
// would compute the same way is a name anyone with keyforge knows to look for. It carries no
// folder and no word, so in a listing it is one more entry among the others rather than a
// labelled compartment.
//
// The cost is worth stating: lose the config and the entry is orphaned — a meaningless name
// nobody can connect to anything. That is survivable because the rule kept there is a
// convenience; what stands behind the marker has to be remembered regardless.
func GenerateName() (string, error) {
	var b [5]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

// ValidateRule refuses a rule that cannot work, before it is stored rather than after it has
// produced a sheet nobody can read.
func ValidateRule(r Rule) error {
	if r.StripN < 0 {
		return fmt.Errorf("the insert count cannot be negative")
	}
	if r.StripN > 0 && r.Strip == "" {
		return fmt.Errorf("there are no characters to scatter")
	}
	if strings.Contains(r.Strip, sep) {
		return fmt.Errorf("%q cannot be one of the noise characters — it separates the stored fields", sep)
	}
	for _, c := range r.Strip {
		if _, clash := r.Markers[c]; clash {
			return fmt.Errorf("%q is both noise and a marker — it cannot be both deleted and expanded", c)
		}
	}
	for k, v := range r.Markers {
		if v == "" {
			return fmt.Errorf("marker %q has nothing behind it", k)
		}
		if strings.ContainsAny(v, "\n\r"+sep) {
			return fmt.Errorf("what stands behind %q cannot contain a newline or %q", k, sep)
		}
		// A comma separates one marker=value pair from the next wherever they are typed, so a
		// value containing one cannot be entered again — refused here rather than discovered
		// the day the rule has to be retyped.
		if strings.ContainsRune(v, ',') {
			return fmt.Errorf("what stands behind %q cannot contain a comma — it separates the pairs", k)
		}
		// A value carrying a reserved character puts that character INSIDE the password, where
		// the rule has already promised it can only be noise. The round trip still holds — Apply
		// does not rescan what it expanded — but the password is then unprintable for ever:
		// ComposeExisting refuses it, and the message blames the password rather than the rule
		// that made it. Refused here, once, instead of discovered years later at the one moment
		// the paper is the only copy.
		if i := strings.IndexAny(v, r.Strip); i >= 0 {
			return fmt.Errorf("what stands behind %q contains %q, which the rule deletes as noise — "+
				"the password would carry a character it can never be printed with",
				k, string([]rune(v[i:])[0]))
		}
		for other := range r.Markers {
			if strings.ContainsRune(v, other) {
				return fmt.Errorf("what stands behind %q contains %q, which is itself a marker", k, string(other))
			}
		}
		if string(k) == sep {
			return fmt.Errorf("%q cannot be a marker — it separates the stored fields", sep)
		}
	}
	return nil
}

// Total is how many characters the rule adds, so a generated password can be made that much
// shorter and land on the round number that was asked for.
func (r Rule) Total() int { return r.StripN + len(r.Markers) }
