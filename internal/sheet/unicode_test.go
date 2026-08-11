package sheet

import (
	"strings"
	"testing"
)

// TestComposeApplyAreRuneSafe: a marker's value is whatever the user memorised, and people
// memorise words in their own alphabet. Everything here counts runes rather than bytes, and the
// round trip is the place a byte/rune mix-up would surface as a sheet that decodes to nonsense.
func TestComposeApplyAreRuneSafe(t *testing.T) {
	m := Mask{Strip: "q7", StripN: 3, Expand: map[rune]string{'z': "МОЯТА-ДУМА"}}
	base := "коренлампаvodopad"
	paper, real := Compose(base, m)

	if strings.Contains(paper, "МОЯТА-ДУМА") {
		t.Errorf("the remembered part is legible on the paper: %q", paper)
	}
	if !strings.Contains(real, "МОЯТА-ДУМА") {
		t.Errorf("the remembered part never reached the password: %q", real)
	}
	if got := Apply(paper, m); got != real {
		t.Fatalf("round trip broken:\n  paper %q\n  got   %q\n  want  %q", paper, got, real)
	}
	// The overheads are rune counts, not byte counts: "МОЯТА-ДУМА" is 10 runes and 19 bytes,
	// and a length computed from the latter would make every password nine characters short.
	if got := m.RealOverhead(); got != 10 {
		t.Errorf("RealOverhead = %d, want 10 runes", got)
	}
}

// TestComposeExistingIsRuneSafe: the refusal scans runes, so a multi-byte password must not be
// refused for a byte that merely happens to sit inside one of its characters.
func TestComposeExistingIsRuneSafe(t *testing.T) {
	m := Mask{Strip: "q7", StripN: 2}
	secret := "паролата-ми-е-дълга"
	paper, _, err := ComposeExisting(secret, m)
	if err != nil {
		t.Fatalf("refused a password with no reserved characters: %v", err)
	}
	if got := Apply(paper, m); got != secret {
		t.Fatalf("round trip broken:\n  paper %q\n  got   %q\n  want  %q", paper, got, secret)
	}
}
