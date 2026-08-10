package sheet

import (
	"strings"
	"testing"

	"github.com/lvim-tech/keyforge/internal/passgen"
)

// stripReserved is what a human does by eye when reading the sheet: delete every reserved
// character. The whole scheme rests on this being an exact inverse of Decoy, so it is tested as
// such rather than assumed.
func stripReserved(s, reserved string) string {
	return strings.Map(func(r rune) rune {
		if strings.ContainsRune(reserved, r) {
			return -1
		}
		return r
	}, s)
}

func TestDecoyRoundTripPhrase(t *testing.T) {
	const reserved = "q7"
	o := passgen.DefaultPhraseOptions()
	o.Reserved = reserved

	for i := 0; i < 300; i++ {
		secret, _, err := passgen.Phrase(o)
		if err != nil {
			t.Fatalf("Phrase: %v", err)
		}
		if strings.ContainsAny(secret, reserved) {
			t.Fatalf("the generator produced a reserved character: %q", secret)
		}
		printed := Decoy(secret, reserved, 3)
		if got := stripReserved(printed, reserved); got != secret {
			t.Fatalf("does not reconstruct:\n  on sheet : %q\n  want     : %q\n  got      : %q", printed, secret, got)
		}
	}
}

func TestDecoyRoundTripPassword(t *testing.T) {
	const reserved = "q7"
	o := passgen.DefaultOptions()
	o.Reserved = reserved

	for i := 0; i < 300; i++ {
		secret, _, err := passgen.Password(o)
		if err != nil {
			t.Fatalf("Password: %v", err)
		}
		if strings.ContainsAny(secret, reserved) {
			t.Fatalf("the generator produced a reserved character: %q", secret)
		}
		printed := Decoy(secret, reserved, 2)
		if got := stripReserved(printed, reserved); got != secret {
			t.Fatalf("does not reconstruct: %q → %q, want %q", printed, got, secret)
		}
	}
}

// The noise must not land on the first or last two characters — those are the positions an eye
// lands on first, and on a phrase they deform the opening word.
func TestDecoyAvoidsEdges(t *testing.T) {
	const reserved = "#"
	secret := "abcdefghijklmnopqrstuvwxyz"
	for i := 0; i < 500; i++ {
		printed := Decoy(secret, reserved, 1)
		idx := strings.Index(printed, reserved)
		if idx < 2 || idx > len(printed)-3 {
			t.Fatalf("noise at the edge: position %d in %q", idx, printed)
		}
	}
}

// A secret too short to hide anything inside must come back untouched rather than be mangled.
func TestDecoyShortSecret(t *testing.T) {
	if got := Decoy("abc", "q", 2); got != "abc" {
		t.Fatalf("a short string was altered: %q", got)
	}
	if got := Decoy("abcdef", "", 2); got != "abcdef" {
		t.Fatalf("with no reserved characters nothing should change: %q", got)
	}
}

// Placement must vary. Predictable positions would let anyone holding two sheets line them up and
// subtract the noise without knowing the rule at all.
func TestDecoyPositionsVary(t *testing.T) {
	const reserved = "#"
	secret := strings.Repeat("ab", 16)
	seen := map[int]bool{}
	for i := 0; i < 200; i++ {
		seen[strings.Index(Decoy(secret, reserved, 1), reserved)] = true
	}
	if len(seen) < 10 {
		t.Fatalf("the positions do not vary enough: only %d distinct", len(seen))
	}
}
