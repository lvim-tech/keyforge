package sheet

import (
	"errors"
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

// RealOverhead is how many characters the markers add to the PASSWORD, as opposed to the paper.
//
// The two differ and both are needed. A marker is INSERTED into the base rather than replacing
// one of its characters, so on the paper it costs one character and in the password it costs the
// whole of what it stands for. The generator that shows the PAPER subtracts Overhead; the one
// that shows the PASSWORD subtracts this, and both land on the round number the user asked for.
func (m Mask) RealOverhead() int {
	n := 0
	for _, v := range m.Expand {
		n += len([]rune(v))
	}
	return n
}

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

// errReservedInSecret is why an existing password cannot go on a sheet. One value, so callers
// can group refusals under it instead of repeating the same sentence per row.
var errReservedInSecret = errors.New(
	"they already contain a character the rule removes, so the sheet would reconstruct the wrong password")

// ComposeExisting hides a password that ALREADY EXISTS, which is a weaker thing than
// composing one, and the difference is worth stating rather than papering over.
//
// Noise always applies: it is removed by the reader, so what is left is exactly what went in.
//
// MARKERS APPLY WHERE THE PASSWORD ACTUALLY CONTAINS WHAT THEY STAND FOR. A marker is expanded
// on the way back, so it can only replace a run of characters equal to its value — which is
// precisely the case for a password this program generated under the same rule, since the
// value is sitting in it verbatim. Refusing markers outright, as this used to, meant that
// changing a password the proper way and importing it again produced a sheet with only noise
// on it, and no way to tell why. Where the value is not present the marker is dropped, and
// markersDropped says so.
//
// THE ROUND TRIP IS VERIFIED, NOT REASONED ABOUT. After the substitutions the paper is put
// back through Apply and compared with the password; anything short of an exact match falls
// back to noise alone. Marker values can interact — one value can be formed by replacing
// another — and the failure would be a sheet that reconstructs a plausible wrong password.
// That is the one outcome this whole design exists to prevent, so it is checked rather than
// argued.
//
// AND IT REFUSES A PASSWORD THAT ALREADY CONTAINS A RESERVED CHARACTER. This is the whole
// reason the function returns an error. When a password is generated, the generator is told
// which characters are reserved and never produces them, so every one on the paper is
// unambiguously noise. A password that came from somewhere else has made no such promise: if
// the rule says "delete every q" and the password contains a q of its own, the reader deletes
// that too and reconstructs something that is not the password. The sheet would look
// perfectly ordinary and be wrong — discovered at the one moment a paper backup is ever
// used, which is the moment nothing else is left.
func ComposeExisting(secret string, m Mask) (paper string, markersDropped bool, err error) {
	// The offending CHARACTER is not named, and that is deliberate rather than terse. The
	// reader can do nothing with it — the rule cannot be edited, and the remedy is the same
	// either way — while a list of refusals that each names its character prints the noise set
	// in a neat column for anyone looking at the screen. That is the one thing the interface
	// spent the rest of its design not saying.
	reserved := m.Reserved()
	for _, r := range secret {
		if strings.ContainsRune(reserved, r) {
			return "", false, errReservedInSecret
		}
	}
	body, applied := m.placeMarkers(secret)
	if Apply(body, m) != secret {
		body, applied = secret, 0
	}

	out := []rune(body)
	strip := []rune(m.Strip)
	for i := 0; i < m.StripN && len(strip) > 0; i++ {
		idx, perr := pick(len(strip))
		if perr != nil {
			break
		}
		out = insertRandom(out, strip[idx])
	}
	return string(out), applied < len(m.Expand), nil
}

// placeMarkers substitutes each marker for every occurrence of what it stands for, and reports
// how many markers found a home.
//
// Longest value first, so that a value which contains another is consumed before its own
// substring can be taken out from under it.
func (m Mask) placeMarkers(secret string) (string, int) {
	keys := m.expandKeys()
	sort.Slice(keys, func(i, j int) bool { return len(m.Expand[keys[i]]) > len(m.Expand[keys[j]]) })
	applied := 0
	for _, k := range keys {
		v := m.Expand[k]
		if v == "" || !strings.Contains(secret, v) {
			continue
		}
		secret = strings.ReplaceAll(secret, v, string(k))
		applied++
	}
	return secret, applied
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
