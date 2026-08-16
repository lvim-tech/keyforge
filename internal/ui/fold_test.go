package ui

import (
	"strings"
	"testing"
)

// TestFoldRunesKeepsWhitespace is the regression test for the reveal pane. wrapText works in
// strings.Fields, so it collapses runs of whitespace — harmless in prose and wrong on the one
// feature whose entire job is showing exactly what is stored. A password of "korap  vezna" was
// displayed as "korap vezna", typed into a phone, and did not work.
func TestFoldRunesKeepsWhitespace(t *testing.T) {
	for _, s := range []string{"korap  vezna", " leading", "trailing ", "a\tb", "one two three"} {
		if got := foldRunes(s, 80); got != s {
			t.Errorf("foldRunes(%q) = %q — the value changed", s, got)
		}
	}
	// The old behaviour, kept here so the difference is not theoretical.
	if wrapText("korap  vezna", 80) == "korap  vezna" {
		t.Skip("wrapText no longer collapses whitespace; foldRunes may be redundant")
	}
}

// TestFoldRunesFoldsByRunes: the fold is by character, so a Cyrillic passphrase is not cut in half
// at a byte boundary, and rejoining the lines gives the value back exactly.
func TestFoldRunesFoldsByRunes(t *testing.T) {
	in := "абвгдежзийклмноп"
	out := foldRunes(in, 5)
	lines := strings.Split(out, "\n")
	if len(lines) != 4 {
		t.Fatalf("got %d lines: %q", len(lines), out)
	}
	for _, l := range lines[:len(lines)-1] {
		if n := len([]rune(l)); n != 5 {
			t.Errorf("line %q is %d runes, want 5", l, n)
		}
	}
	if joined := strings.Join(lines, ""); joined != in {
		t.Errorf("the value did not survive folding: %q", joined)
	}
}

func TestFoldRunesShortAndDegenerate(t *testing.T) {
	if got := foldRunes("abc", 10); got != "abc" {
		t.Errorf("got %q", got)
	}
	if got := foldRunes("", 10); got != "" {
		t.Errorf("got %q", got)
	}
	if got := foldRunes("ab", 0); got != "a\nb" {
		t.Errorf("a width below one must still make progress, got %q", got)
	}
}
