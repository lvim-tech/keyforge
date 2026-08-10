package sys

import (
	"os"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestHardenDisablesCoreDumps(t *testing.T) {
	var before unix.Rlimit
	_ = unix.Getrlimit(unix.RLIMIT_CORE, &before)
	done := Harden()
	var after unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_CORE, &after); err != nil {
		t.Fatal(err)
	}
	if after.Cur != 0 {
		t.Fatalf("RLIMIT_CORE is %d, want 0 (was %d)", after.Cur, before.Cur)
	}
	if len(done) == 0 {
		t.Fatal("Harden reported nothing")
	}
	t.Logf("before: %d → after: %d   [%s]", before.Cur, after.Cur, strings.Join(done, ", "))
}

func TestSecretWipes(t *testing.T) {
	s, err := NewSecret(64)
	if err != nil {
		t.Fatal(err)
	}
	s.Append([]byte("Qx9"))
	if s.Len() != 3 || s.Empty() {
		t.Fatalf("length %d", s.Len())
	}
	var got string
	s.Use(func(v string) { got = v })
	if got != "Qx9" {
		t.Fatalf("got %q", got)
	}
	// A wipe must leave nothing behind in the buffer itself.
	raw := s.buf
	s.Reset()
	for i, b := range raw[:8] {
		if b != 0 {
			t.Fatalf("byte %d was not zeroed: %d", i, b)
		}
	}
	if !s.Empty() {
		t.Fatal("Reset does not empty the buffer")
	}
	s.Close()
}

func TestSecretBackspaceUTF8(t *testing.T) {
	s, _ := NewSecret(64)
	defer s.Close()
	s.Append([]byte("абв")) // Cyrillic: two bytes per character
	if s.Len() != 3 {
		t.Fatalf("length %d instead of 3", s.Len())
	}
	s.Backspace()
	var got string
	s.Use(func(v string) { got = v })
	if got != "аб" {
		t.Fatalf("after Backspace: %q — a two-byte character was cut in half", got)
	}
}

func TestSecretLocked(t *testing.T) {
	s, err := NewSecret(64)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if !s.Locked() {
		var lim unix.Rlimit
		_ = unix.Getrlimit(unix.RLIMIT_MEMLOCK, &lim)
		t.Logf("the buffer is NOT locked (RLIMIT_MEMLOCK=%d) — on this machine swap can reach it", lim.Cur)
	}
}

func TestSwapWarningShape(t *testing.T) {
	w := SwapWarning()
	b, _ := os.ReadFile("/proc/swaps")
	lines := len(strings.Split(strings.TrimSpace(string(b)), "\n"))
	if lines <= 1 && w != "" {
		t.Fatalf("no swap, yet a warning was produced: %q", w)
	}
	t.Logf("swap: %q", w)
}
