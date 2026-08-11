package sheet

import (
	"strings"
	"testing"
)

func TestComposeExistingSurvivesTheRoundTrip(t *testing.T) {
	m := Mask{Strip: "q7", StripN: 3}
	secret := "koren-lampa-vodopad"
	paper, dropped, err := ComposeExisting(secret, m)
	if err != nil {
		t.Fatalf("refused a password with no reserved characters: %v", err)
	}
	if dropped {
		t.Errorf("no markers were configured, yet it reported dropping some")
	}
	if paper == secret {
		t.Errorf("no noise was added: %q", paper)
	}
	if got := Apply(paper, m); got != secret {
		t.Errorf("the sheet does not reconstruct the password:\n  paper %q\n  got   %q\n  want  %q", paper, got, secret)
	}
}

func TestComposeExistingRefusesAPasswordItWouldCorrupt(t *testing.T) {
	// The founding case for this refusal: the rule deletes every q, and the password has
	// two of its own. Printed, the sheet would reconstruct "uick-brown-fox-" and nobody
	// would find out until the paper was the only copy left.
	m := Mask{Strip: "q7", StripN: 3}
	if _, _, err := ComposeExisting("quick-brown-fox-7", m); err == nil {
		t.Fatal("accepted a password the sheet cannot reconstruct")
	}
}

func TestComposeExistingUsesAMarkerThePasswordActuallyContains(t *testing.T) {
	// The case that matters: a password made under this very rule carries the marker's value
	// verbatim, so the marker can go back onto the paper and the sheet stops naming it.
	m := Mask{Strip: "q7", StripN: 3, Expand: map[rune]string{'z': "Qx9"}}
	secret := "resume-waller-Qx9-lowly"
	paper, dropped, err := ComposeExisting(secret, m)
	if err != nil {
		t.Fatalf("unexpected refusal: %v", err)
	}
	if dropped {
		t.Errorf("the value was present and the marker was dropped anyway")
	}
	if strings.Contains(paper, "Qx9") {
		t.Errorf("the value is still legible on the paper: %q", paper)
	}
	if !strings.ContainsRune(paper, 'z') {
		t.Errorf("the marker never reached the paper: %q", paper)
	}
	if got := Apply(paper, m); got != secret {
		t.Errorf("round trip broken:\n  paper %q\n  got   %q\n  want  %q", paper, got, secret)
	}
}

func TestComposeExistingFallsBackWhenMarkersWouldCorrupt(t *testing.T) {
	// Two markers whose values interact: substituting the first creates the second's value out
	// of thin air, and expanding both back would reconstruct something else. The verification
	// has to catch it and keep the noise alone.
	m := Mask{Strip: "-", StripN: 2, Expand: map[rune]string{'z': "AB", 'w': "zC"}}
	secret := "xxABCxx"
	paper, dropped, err := ComposeExisting(secret, m)
	if err != nil {
		t.Fatalf("unexpected refusal: %v", err)
	}
	if !dropped {
		t.Errorf("it claimed the markers applied")
	}
	if got := Apply(paper, m); got != secret {
		t.Fatalf("a sheet that reconstructs the wrong password:\n  paper %q\n  got   %q\n  want  %q", paper, got, secret)
	}
}

func TestComposeExistingSaysWhenMarkersCannotApply(t *testing.T) {
	// The value is nowhere in the password, so the marker has nothing to replace.
	m := Mask{Strip: "q", StripN: 1, Expand: map[rune]string{'z': "SECRET"}}
	paper, dropped, err := ComposeExisting("already-chosen", m)
	if err != nil {
		t.Fatalf("unexpected refusal: %v", err)
	}
	if !dropped {
		t.Errorf("markers were configured and it did not say they were dropped")
	}
	if got := Apply(paper, m); got != "already-chosen" {
		t.Errorf("round trip broken: %q", got)
	}
}
