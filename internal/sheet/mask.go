package sheet

import (
	"sort"
	"strings"
)

// Mask is the difference between what a sheet SHOWS and what the password IS.
//
// Two rules, both carried by ordinary characters the generator is forbidden to produce, so a
// printed value looks like any other password and nothing on the page announces that a rule exists.
//
//	Strip   characters inserted as pure noise. You delete them when reading.
//	Expand  characters that stand for something you memorised. You substitute them when reading.
//
// THEY ARE NOT EQUALLY STRONG, and it is worth being exact about why.
//
// Strip hides the rule, not the secret: the page holds every character of the password plus some
// litter, so anyone who learns the rule — from the tool, from a second sheet, from a habit — reads
// the password straight off. Its value is entirely in the rule staying unknown.
//
// Expand hides the secret itself. The page is genuinely missing something that was never written
// anywhere, and no amount of studying the page recovers it. Someone holding the sheet must guess
// the expansion; someone holding nothing must guess the whole password.
//
// One honest limit on Expand: the same expansion is reused across entries, so it adds nothing
// against an attacker who never sees the paper — for them the password is simply as long as it is.
// It buys exactly one thing, and buys it completely: the paper alone is not enough.
type Mask struct {
	Strip  string          // characters inserted as noise, deleted on reading
	StripN int             // how many noise characters to scatter
	Expand map[rune]string // marker → what it really stands for
}

// Reserved returns every character the generator must never emit. A character that could appear
// naturally would make the rule ambiguous — you would not know whether to delete it or keep it —
// and an ambiguous rule applied at four in the morning is a password you cannot type.
func (m Mask) Reserved() string {
	var sb strings.Builder
	sb.WriteString(m.Strip)
	keys := m.expandKeys()
	for _, r := range keys {
		sb.WriteRune(r)
	}
	return sb.String()
}

// expandKeys returns the markers in a stable order, so composing twice gives the same layout for
// the same random draws and the tests mean something.
func (m Mask) expandKeys() []rune {
	keys := make([]rune, 0, len(m.Expand))
	for r := range m.Expand {
		keys = append(keys, r)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
	return keys
}

// Overhead is how many characters the mask adds to the printed value. The generator subtracts it
// from the requested length so the sheet comes out at the round number the user asked for — a
// 20-character password that prints as 22 is a small tell, and a small tell is still a tell.
func (m Mask) Overhead() int { return m.StripN + len(m.Expand) }

// Empty reports whether the mask does nothing, in which case paper and password are the same.
func (m Mask) Empty() bool { return m.StripN <= 0 && len(m.Expand) == 0 }

// Compose turns a generated base into the pair that matters: what goes on the paper, and what the
// password actually is. Both are derived from the same insertion so they cannot drift apart —
// deriving them separately is how a sheet ends up not matching the account it was printed for.
func Compose(base string, m Mask) (paper, real string) {
	if m.Empty() {
		return base, base
	}
	out := []rune(base)

	// Markers first, then noise. The noise is allowed to land beside a marker, which is the point:
	// if noise never touched the markers, the markers would sit at recognisably clean positions.
	for _, marker := range m.expandKeys() {
		out = insertRandom(out, marker)
	}
	strip := []rune(m.Strip)
	for i := 0; i < m.StripN && len(strip) > 0; i++ {
		idx, err := pick(len(strip))
		if err != nil {
			break
		}
		out = insertRandom(out, strip[idx])
	}

	paper = string(out)
	real = Apply(paper, m)
	return paper, real
}

// Apply performs, in code, exactly what the reader does by eye: delete the noise, substitute the
// markers. Keeping it as one function means the rule has a single definition — the tests check that
// definition against Compose, and the sheet's own instructions are written from it.
func Apply(paper string, m Mask) string {
	var sb strings.Builder
	for _, r := range paper {
		switch {
		case strings.ContainsRune(m.Strip, r):
			// noise: gone
		case m.Expand != nil && m.Expand[r] != "":
			sb.WriteString(m.Expand[r])
		default:
			sb.WriteRune(r)
		}
	}
	return sb.String()
}

// insertRandom puts r somewhere inside s, never in the first or last two positions.
func insertRandom(s []rune, r rune) []rune {
	if len(s) < 6 {
		return append(s, r)
	}
	pos, err := pick(len(s) - 4)
	if err != nil {
		return s
	}
	pos += 2
	return append(s[:pos], append([]rune{r}, s[pos:]...)...)
}

// Legend describes the rule in words, for the person setting it up. It is deliberately NOT printed
// on the sheet: a page that explains how to decode itself is a page that decodes itself for whoever
// picks it up.
func (m Mask) Legend() string {
	var parts []string
	if m.StripN > 0 && m.Strip != "" {
		parts = append(parts, "remove "+strings.Join(strings.Split(m.Strip, ""), " and "))
	}
	for _, r := range m.expandKeys() {
		parts = append(parts, string(r)+" → "+m.Expand[r])
	}
	if len(parts) == 0 {
		return "no masking — the sheet holds the passwords themselves"
	}
	return strings.Join(parts, ", ")
}
