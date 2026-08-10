package sheet

import (
	"strings"
	"testing"

	"github.com/lvim-tech/keyforge/internal/passgen"
)

func testMask() Mask {
	return Mask{Strip: "q7", StripN: 2, Expand: map[rune]string{'z': "Qx9", 'j': "!Bg"}}
}

// The generator must never produce a reserved character, otherwise the rule is ambiguous.
func TestGeneratorAvoidsReserved(t *testing.T) {
	m := testMask()
	co := passgen.DefaultOptions()
	co.Reserved = m.Reserved()
	po := passgen.DefaultPhraseOptions()
	po.Reserved = m.Reserved()
	for i := 0; i < 300; i++ {
		s, _, err := passgen.Password(co)
		if err != nil {
			t.Fatal(err)
		}
		if strings.ContainsAny(s, m.Reserved()) {
			t.Fatalf("character mode produced a reserved character: %q", s)
		}
		p, _, err := passgen.Phrase(po)
		if err != nil {
			t.Fatal(err)
		}
		if strings.ContainsAny(p, m.Reserved()) {
			t.Fatalf("the phrase produced a reserved character: %q", p)
		}
	}
}

// Reading the paper by the rule must land exactly on the password Compose reported.
func TestComposeApplyAgree(t *testing.T) {
	m := testMask()
	co := passgen.DefaultOptions()
	co.Reserved = m.Reserved()
	for i := 0; i < 500; i++ {
		base, _, err := passgen.Password(co)
		if err != nil {
			t.Fatal(err)
		}
		paper, real := Compose(base, m)
		if got := Apply(paper, m); got != real {
			t.Fatalf("the rule does not round-trip:\n  sheet  %q\n  want   %q\n  got    %q", paper, real, got)
		}
	}
}

// The paper must carry every marker exactly once, and the noise count must be what was asked for.
func TestComposeCounts(t *testing.T) {
	m := testMask()
	co := passgen.DefaultOptions()
	co.Reserved = m.Reserved()
	for i := 0; i < 200; i++ {
		base, _, _ := passgen.Password(co)
		paper, _ := Compose(base, m)
		for marker := range m.Expand {
			if n := strings.Count(paper, string(marker)); n != 1 {
				t.Fatalf("marker %q appears %d times in %q", marker, n, paper)
			}
		}
		noise := 0
		for _, r := range paper {
			if strings.ContainsRune(m.Strip, r) {
				noise++
			}
		}
		if noise != m.StripN {
			t.Fatalf("noise %d instead of %d in %q", noise, m.StripN, paper)
		}
	}
}

// Length compensation: the printed value must come out at the requested length.
func TestPrintedLengthIsRound(t *testing.T) {
	m := testMask()
	const want = 20
	co := passgen.DefaultOptions()
	co.Reserved = m.Reserved()
	co.Length = want - m.Overhead()
	for i := 0; i < 200; i++ {
		base, _, _ := passgen.Password(co)
		paper, _ := Compose(base, m)
		if len([]rune(paper)) != want {
			t.Fatalf("the sheet is %d characters instead of %d: %q", len([]rune(paper)), want, paper)
		}
	}
}

// An empty mask must be a no-op, so the feature can simply be off.
func TestEmptyMask(t *testing.T) {
	var m Mask
	paper, real := Compose("abcdef", m)
	if paper != "abcdef" || real != "abcdef" {
		t.Fatalf("the empty mask changes the value: %q / %q", paper, real)
	}
	if m.Reserved() != "" {
		t.Fatalf("the empty mask reserves characters: %q", m.Reserved())
	}
}
