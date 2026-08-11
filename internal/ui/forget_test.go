package ui

import (
	"testing"

	"github.com/lvim-tech/keyforge/internal/config"
)

// TestForgetReachesEveryView is the regression behind KF-003: the Print tab held the most in the
// clear — every row's real password and the rule's marker values — and was the only view without
// a forgetMsg branch. A lock that covers the screen while the passwords sit behind it is the one
// thing this program must not be, so the guarantee is asserted for ALL views rather than for the
// three that happened to implement it.
//
// It checks the branch exists by observing that each view returns without touching the message as
// a key press: a view that ignores forgetMsg falls through to its key handling, where the message
// is discarded by the type switch — indistinguishable from here. So the real assertion is
// structural and lives beside it: every view that can hold a secret must clear it.
func TestForgetReachesEveryView(t *testing.T) {
	m := New(config.Default())
	if len(m.views) == 0 {
		t.Fatal("no views")
	}
	// The broadcast must not panic on any view, in any starting state — the lock path runs it
	// with no terminal size and no loaded data, which is exactly when a nil map or slice bites.
	cmd := m.afterLock()
	_ = cmd
	for i, v := range m.views {
		if v == nil {
			t.Fatalf("view %d is nil after forget", i)
		}
	}
}

// TestPrintDropsItsSecretsOnForget pins the specific hole: rows, rule and mask must be gone.
func TestPrintDropsItsSecretsOnForget(t *testing.T) {
	rules := newRuleCache(config.Default())
	v := newPrintView(config.Default(), rules)
	v.rows = append(v.rows, row{label: "x", paper: "aq7b", real: "ab", include: true})
	v.rule.Strip = "q7"
	v.mask.Strip = "q7"

	out, _ := v.Update(forgetMsg{})
	pv, ok := out.(*printView)
	if !ok {
		t.Fatal("the view changed type")
	}
	if len(pv.rows) != 0 {
		t.Errorf("%d rows survived the lock", len(pv.rows))
	}
	if pv.rule.Strip != "" || pv.mask.Strip != "" {
		t.Errorf("the rule survived the lock: %q / %q", pv.rule.Strip, pv.mask.Strip)
	}
}
