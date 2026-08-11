package sheet

import (
	"strings"
	"testing"

	"github.com/lvim-tech/keyforge/internal/passgen"
)

// These tests used to cover `Decoy`, the mechanism Mask/Compose replaced. Decoy had been dead
// code for some time — nothing outside its own tests called it — so the FUNCTION is gone and the
// properties it guaranteed are asserted here against the code that actually runs.

// TestComposeRoundTripPhrase and its password twin are the whole promise of a printed sheet: what
// the reader does by eye must return exactly what the account has.
func TestComposeRoundTripPhrase(t *testing.T) {
	m := Mask{Strip: "q7", StripN: 3}
	o := passgen.DefaultPhraseOptions()
	o.Reserved = m.Reserved()
	for i := 0; i < 200; i++ {
		base, _, err := passgen.Phrase(o)
		if err != nil {
			t.Fatal(err)
		}
		paper, real := Compose(base, m)
		if paper == real {
			t.Fatalf("nothing was inserted: %q", paper)
		}
		if got := Apply(paper, m); got != real {
			t.Fatalf("the sheet does not reconstruct the password:\n  paper %q\n  got   %q\n  want  %q", paper, got, real)
		}
	}
}

func TestComposeRoundTripPassword(t *testing.T) {
	m := Mask{Strip: "q7", StripN: 2, Expand: map[rune]string{'z': "Qx9"}}
	o := passgen.DefaultOptions()
	o.SymbolsAll = true
	o.Reserved = m.Reserved()
	for i := 0; i < 200; i++ {
		base, _, err := passgen.Password(o)
		if err != nil {
			t.Fatal(err)
		}
		paper, real := Compose(base, m)
		if strings.Contains(paper, "Qx9") {
			t.Fatalf("the remembered part is legible on the paper: %q", paper)
		}
		if got := Apply(paper, m); got != real {
			t.Fatalf("round trip broken:\n  paper %q\n  got   %q\n  want  %q", paper, got, real)
		}
	}
}

// TestInsertRandomAvoidsEdges: noise at an edge is the first thing an eye notices, and on a word
// phrase it deforms the opening syllable — which is what makes the line hard to read back.
func TestInsertRandomAvoidsEdges(t *testing.T) {
	base := []rune("abcdefghijklmnop")
	for i := 0; i < 500; i++ {
		out := insertRandom(append([]rune(nil), base...), 'q')
		at := strings.IndexRune(string(out), 'q')
		if at < 2 || at > len(out)-3 {
			t.Fatalf("inserted at %d, too close to an edge: %q", at, string(out))
		}
	}
}

// TestInsertRandomShortSecret: below the width where an interior position exists, appending is
// the honest fallback — it must still insert rather than silently drop the character.
func TestInsertRandomShortSecret(t *testing.T) {
	out := insertRandom([]rune("abc"), 'q')
	if !strings.ContainsRune(string(out), 'q') {
		t.Fatalf("the character was dropped: %q", string(out))
	}
}

// TestInsertRandomPositionsVary: a fixed position would be a pattern, and a pattern across a
// page of passwords is the rule written down in a different alphabet.
func TestInsertRandomPositionsVary(t *testing.T) {
	seen := map[int]bool{}
	base := []rune("abcdefghijklmnopqrstuvwxyz")
	for i := 0; i < 200; i++ {
		out := insertRandom(append([]rune(nil), base...), '7')
		seen[strings.IndexRune(string(out), '7')] = true
	}
	if len(seen) < 5 {
		t.Errorf("only %d distinct positions in 200 draws", len(seen))
	}
}
