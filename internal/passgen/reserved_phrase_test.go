package passgen

import (
	"strings"
	"testing"
)

func TestPhraseNumberAvoidsReservedDigits(t *testing.T) {
	o := DefaultPhraseOptions()
	o.Reserved = "7"
	o.Number = true
	for i := 0; i < 500; i++ {
		s, _, err := Phrase(o)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(s, "7") {
			t.Fatalf("a reserved digit reached the phrase: %q", s)
		}
	}
}

func TestPhraseRefusesAReservedSeparator(t *testing.T) {
	o := DefaultPhraseOptions()
	o.Separator = "-"
	o.Reserved = "-"
	if _, _, err := Phrase(o); err == nil {
		t.Fatal("accepted a separator the rule deletes")
	}
}
