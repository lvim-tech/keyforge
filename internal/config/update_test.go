package config

import (
	"os"
	"path/filepath"
	"testing"
)

// TestTwoViewsDoNotRevertEachOther is the regression the audit named: each tab held a copy of
// the config taken at startup and saved the whole of it, so the second saver undid the first.
// The one that mattered was sheet.rule_from — a random name nobody can rediscover.
func TestTwoViewsDoNotRevertEachOther(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	if err := os.MkdirAll(filepath.Join(dir, "keyforge"), 0o700); err != nil {
		t.Fatal(err)
	}

	// Both views load the same starting state.
	settingsCopy, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	printCopy, err := Load()
	if err != nil {
		t.Fatal(err)
	}

	// Settings changes a lock setting and writes only what it owns.
	settingsCopy.Lock.IdleMinutes = 5
	if _, err := Update(func(c *Config) { c.Lock = settingsCopy.Lock }); err != nil {
		t.Fatal(err)
	}

	// Print stores a rule from its now-stale copy and writes only that field.
	printCopy.Sheet.RuleFrom = "f644307786"
	if _, err := Update(func(c *Config) { c.Sheet.RuleFrom = printCopy.Sheet.RuleFrom }); err != nil {
		t.Fatal(err)
	}

	got, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if got.Lock.IdleMinutes != 5 {
		t.Errorf("the lock setting was reverted: idle_minutes = %d", got.Lock.IdleMinutes)
	}
	if got.Sheet.RuleFrom != "f644307786" {
		t.Errorf("the rule pointer was lost: rule_from = %q", got.Sheet.RuleFrom)
	}
}
