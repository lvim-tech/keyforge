package sheet

import (
	"strings"
	"testing"
)

func TestRuleSurvivesTheRoundTrip(t *testing.T) {
	r := Rule{Strip: "q7", StripN: 3, Markers: map[rune]string{'z': "Qx9", 'j': "дума"}}
	got := DecodeRule(r.Encode())
	if got.Strip != r.Strip || got.StripN != r.StripN || len(got.Markers) != 2 {
		t.Fatalf("decoded %+v", got)
	}
	if got.Markers['z'] != "Qx9" || got.Markers['j'] != "дума" {
		t.Errorf("markers came back wrong: %+v", got.Markers)
	}
}

func TestEncodedRuleAnnouncesNothing(t *testing.T) {
	// An entry that says "keyforge" or "strip:" tells whoever opens it exactly what it is.
	// A store is full of one-line entries; this must look like one more of them.
	got := Rule{Strip: "q7", StripN: 3, Markers: map[rune]string{'z': "Qx9"}}.Encode()
	for _, word := range []string{"keyforge", "strip", "marker", "count", "rule"} {
		if strings.Contains(strings.ToLower(got), word) {
			t.Errorf("the entry names itself with %q: %q", word, got)
		}
	}
	if strings.Count(strings.TrimSpace(got), "\n") != 0 {
		t.Errorf("more than one line: %q", got)
	}
}

func TestGeneratedNamesDifferBetweenInstallations(t *testing.T) {
	// A name every keyforge would compute the same way is a name anyone with keyforge knows
	// to look for.
	a, err := GenerateName()
	if err != nil {
		t.Fatal(err)
	}
	b, _ := GenerateName()
	if a == b || a == "" {
		t.Errorf("names are not random: %q %q", a, b)
	}
	for _, word := range []string{"keyforge", "rule", "sheet"} {
		if strings.Contains(a, word) {
			t.Errorf("the name says what it is: %q", a)
		}
	}
}

func TestValidateRefusesWhatCannotWork(t *testing.T) {
	cases := map[string]Rule{
		"a character that is both noise and marker": {Strip: "z", StripN: 1, Markers: map[rune]string{'z': "x"}},
		"a marker with nothing behind it":           {Markers: map[rune]string{'z': ""}},
		"scattering with nothing to scatter":        {StripN: 2},
		"a value carrying a newline":                {Markers: map[rune]string{'z': "a\nb"}},
	}
	for name, r := range cases {
		if err := ValidateRule(r); err == nil {
			t.Errorf("accepted %s", name)
		}
	}
	if err := ValidateRule(Rule{Strip: "q7", StripN: 3, Markers: map[rune]string{'z': "Qx9"}}); err != nil {
		t.Errorf("refused a workable rule: %v", err)
	}
}

func TestValidateRefusesAValueCarryingAReservedCharacter(t *testing.T) {
	// The password would come out containing a character the rule deletes as noise, so it could
	// never be printed again — and ComposeExisting would blame the password, not the rule.
	if err := ValidateRule(Rule{Strip: "q7", StripN: 1, Markers: map[rune]string{'z': "aq"}}); err == nil {
		t.Error("accepted a value containing a noise character")
	}
	if err := ValidateRule(Rule{Markers: map[rune]string{'z': "j1", 'j': "x"}}); err == nil {
		t.Error("accepted a value containing another marker")
	}
	if err := ValidateRule(Rule{Strip: "q7", StripN: 1, Markers: map[rune]string{'z': "Qx9"}}); err != nil {
		t.Errorf("refused a perfectly good rule: %v", err)
	}
}

func TestDecodeRuleStrictSeparatesUnreadableFromAbsent(t *testing.T) {
	if _, ok := DecodeRuleStrict("q7:3:z:Qx9"); !ok {
		t.Error("a good rule was reported unreadable")
	}
	for _, bad := range []string{"", "   ", "garbage with no separator"} {
		if _, ok := DecodeRuleStrict(bad); ok {
			t.Errorf("%q was accepted as a rule", bad)
		}
	}
}
