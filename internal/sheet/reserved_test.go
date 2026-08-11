package sheet

import "testing"

func TestReservedIncludesMarkersEvenWithNoValueYet(t *testing.T) {
	// The value is typed at print time and never stored, so at generation time the map has
	// the marker with an empty value. It must still be reserved: the character is claimed
	// the moment it is declared, not when its meaning is supplied.
	m := Mask{Strip: "q7", StripN: 2, Expand: map[rune]string{'z': ""}}
	r := m.Reserved()
	for _, c := range "q7z" {
		if !containsRune(r, c) {
			t.Errorf("%q is not reserved (got %q)", c, r)
		}
	}
}

func containsRune(s string, r rune) bool {
	for _, c := range s {
		if c == r {
			return true
		}
	}
	return false
}
