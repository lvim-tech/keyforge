package config

import (
	"encoding/json"
	"strings"
	"testing"
)

// The guarantee that matters: no field of the persisted type can hold a marker's value, so no
// mistake in the UI can serialise the secret. This test fails the moment someone adds one.
func TestConfigCannotHoldSecrets(t *testing.T) {
	c := Default()
	c.Sheet.Strip = "q7"
	c.Sheet.StripCount = 2
	c.Sheet.SetMarkers("zj")
	b, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	blob := string(b)
	for _, forbidden := range []string{"Qx9", "value", "expand", "secret", "pepper"} {
		if strings.Contains(strings.ToLower(blob), strings.ToLower(forbidden)) {
			t.Fatalf("the serialised config contains %q: %s", forbidden, blob)
		}
	}
	if !strings.Contains(blob, `"markers":["z","j"]`) {
		t.Fatalf("the markers are not written: %s", blob)
	}
}

func TestParseValues(t *testing.T) {
	got, err := ParseValues("z=Qx9, j=!Bg")
	if err != nil {
		t.Fatal(err)
	}
	if got['z'] != "Qx9" || got['j'] != "!Bg" {
		t.Fatalf("got %v", got)
	}
	if _, err := ParseValues("zz=Qx9"); err == nil {
		t.Fatal("a two-character marker must be an error")
	}
	if _, err := ParseValues("z="); err == nil {
		t.Fatal("an empty value must be an error")
	}
}

func TestSetMarkersDedupes(t *testing.T) {
	var s Sheet
	s.SetMarkers("z,z j")
	if len(s.Markers) != 2 {
		t.Fatalf("want 2 markers, got %v", s.Markers)
	}
}
