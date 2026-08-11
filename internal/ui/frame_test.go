package ui

import (
	"strings"
	"testing"

	"github.com/lvim-tech/keyforge/internal/config"
)

// TestFrameNeverExceedsTerminalHeight is the invariant the whole layout rests on: a frame one
// row taller than the terminal makes the terminal scroll, and under the alternate screen the
// row that goes off the TOP is the tab strip — the one that says which tab you are looking at.
//
// The body is sized from the height and the footer is measured, so the arithmetic works out at
// ordinary sizes; it is the small ones that broke it, where a floor handed the body rows that
// did not exist.
func TestFrameNeverExceedsTerminalHeight(t *testing.T) {
	for _, h := range []int{4, 5, 6, 7, 8, 9, 10, 12, 20, 40} {
		for _, w := range []int{60, 110, 200} {
			m := New(config.Default())
			m.w, m.h = w, h
			got := strings.Count(m.View(), "\n") + 1
			if got > h {
				t.Errorf("at %dx%d the frame is %d rows — %d too many", w, h, got, got-h)
			}
		}
	}
}
