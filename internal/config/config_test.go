package config

import (
	"encoding/json"
	"strings"
	"testing"
)

// The config must not be able to hold the rule at all. This is the guarantee that replaced a
// comment: a struct that cannot carry the noise characters or the marker values cannot leak
// them, however careless a later change is. They live encrypted in `pass`; this file keeps
// only the name of that entry.
func TestTheConfigCannotHoldTheRule(t *testing.T) {
	c := Default()
	c.Sheet.RuleFrom = "notes/2026"
	blob, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"strip", "markers", "marker", "values", "expand"} {
		if strings.Contains(strings.ToLower(string(blob)), forbidden) {
			t.Errorf("the serialised config contains %q: %s", forbidden, blob)
		}
	}
	if !strings.Contains(string(blob), "notes/2026") {
		t.Errorf("the pointer was not written: %s", blob)
	}
}

// A name says nothing about what is inside, so an empty one must simply mean "no rule" — not
// an error, not a prompt. Most machines will never have one.
func TestNoRuleIsTheOrdinaryState(t *testing.T) {
	c := Default()
	if c.Sheet.RuleFrom != "" {
		t.Errorf("a fresh config points somewhere: %q", c.Sheet.RuleFrom)
	}
	blob, _ := json.Marshal(c)
	if strings.Contains(string(blob), "rule_from") {
		t.Errorf("an absent rule still leaves a key behind: %s", blob)
	}
}

func TestParseValuesStillRejectsMalformedPairs(t *testing.T) {
	if _, err := ParseValues("zz=two-character-marker"); err == nil {
		t.Error("a two-character marker must be an error")
	}
	if _, err := ParseValues("z="); err == nil {
		t.Error("an empty value must be an error")
	}
	got, err := ParseValues("z=Qx9\nj=other")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got['z'] != "Qx9" {
		t.Errorf("got %v", got)
	}
}
