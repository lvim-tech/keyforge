package sys

import (
	"strings"
	"testing"
)

// TestSecretRecordsOverflow is the regression test for a silent truncation with a nasty shape: the
// password field and its confirmation are the same size, so a value too long for both was cut at
// the same byte in each, compared equal, and went into the store as something the user never typed.
func TestSecretRecordsOverflow(t *testing.T) {
	s, err := NewSecret(8)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	s.Append([]byte("12345678"))
	if s.Overflowed() {
		t.Fatal("a value that fits exactly was reported as overflowed")
	}
	s.Append([]byte("9"))
	if !s.Overflowed() {
		t.Fatal("the dropped byte was not recorded")
	}

	// And the two halves of a too-long password must not compare equal just because both were cut.
	a, _ := NewSecret(8)
	b, _ := NewSecret(8)
	defer a.Close()
	defer b.Close()
	a.Append([]byte("password-one"))
	b.Append([]byte("password-two"))
	if !a.Equal(b) {
		t.Fatal("precondition failed: the two are expected to be indistinguishable after truncation")
	}
	if !a.Overflowed() || !b.Overflowed() {
		t.Fatal("the truncation that makes them look equal was not reported")
	}
}

// TestSecretDoesNotSplitARune: half a character is worse than a missing one — it makes the rune
// count wrong and renders as a replacement character.
func TestSecretDoesNotSplitARune(t *testing.T) {
	s, err := NewSecret(4) // "аб" is four bytes; "абв" is six
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.Append([]byte("абв"))
	if !s.Overflowed() {
		t.Fatal("the dropped character was not recorded")
	}
	got := ""
	s.Use(func(v string) { got = v })
	if got != "аб" {
		t.Errorf("got %q, want %q", got, "аб")
	}
	if s.Len() != 2 {
		t.Errorf("Len = %d, want 2", s.Len())
	}
}

// TestSecretResetClearsOverflow: the flag describes what is in the buffer now, not what once was.
func TestSecretResetClearsOverflow(t *testing.T) {
	s, _ := NewSecret(4)
	defer s.Close()
	s.Append([]byte("abcdef"))
	if !s.Overflowed() {
		t.Fatal("precondition")
	}
	s.Reset()
	if s.Overflowed() {
		t.Error("Reset left the overflow flag set")
	}
	s.Set([]byte("ab"))
	if s.Overflowed() {
		t.Error("Set left the overflow flag set")
	}
}

// TestSecretReadFromAcrossChunks: ReadFrom fills in 512-byte pieces, so a character split across
// two reads must survive — the partial-rune trim must fire only at the capacity boundary.
func TestSecretReadFromAcrossChunks(t *testing.T) {
	body := strings.Repeat("я", 400) // 800 bytes: more than one read chunk
	s, err := NewSecret(4096)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.ReadFrom(strings.NewReader(body)); err != nil {
		t.Fatal(err)
	}
	if s.Overflowed() {
		t.Fatal("a value that fits was reported as overflowed")
	}
	got := ""
	s.Use(func(v string) { got = v })
	if got != body {
		t.Errorf("the value did not survive the chunk boundary (%d runes)", len([]rune(got)))
	}
}

func TestFirstLine(t *testing.T) {
	if got := FirstLine("  gpg: bad passphrase\nmore\n", "fallback"); got != "gpg: bad passphrase" {
		t.Errorf("got %q", got)
	}
	if got := FirstLine("   ", "fallback"); got != "fallback" {
		t.Errorf("got %q", got)
	}
}
