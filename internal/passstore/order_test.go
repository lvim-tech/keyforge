package passstore

import (
	"reflect"
	"testing"
)

// TestArrangeListedFirstRestAlphabetical is the whole rule of a .order file: what it names comes
// first in the order it names it, and what it does not name falls alphabetically after — so
// pinning three folders to the top never means listing the other forty.
func TestArrangeListedFirstRestAlphabetical(t *testing.T) {
	names := []string{"aardvark", "bank", "mail", "websites/", "zulu"}
	got := Arrange([]string{"bank", "websites/"}, names)
	want := []string{"bank", "websites/", "aardvark", "mail", "zulu"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

// TestArrangeIgnoresUnknownAndKeepsEveryName: an .order left behind by a deleted entry must not
// drop or duplicate anything — the list that comes back is the list that went in, rearranged.
func TestArrangeIgnoresUnknownAndKeepsEveryName(t *testing.T) {
	names := []string{"b", "a", "c"}
	got := Arrange([]string{"gone", "c", "also-gone"}, names)
	want := []string{"c", "a", "b"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

// TestArrangeMatchesAFolderWrittenWithoutItsSlash: keyforge writes folders as "name/", and a
// person editing the file by hand writes "name". Both have to pin the same folder, or the file
// stops being editable by hand — which is half the reason it is plain text in the store.
func TestArrangeMatchesAFolderWrittenWithoutItsSlash(t *testing.T) {
	got := Arrange([]string{"websites"}, []string{"apps/", "websites/"})
	want := []string{"websites/", "apps/"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
	// An entry named exactly like the line still wins it: the exact match is tried first, so a
	// record called "websites" is not pinned by a line meant for the folder beside it.
	got = Arrange([]string{"websites"}, []string{"websites/", "websites"})
	want = []string{"websites", "websites/"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

// TestArrangeWithNoOrderIsUntouched: the ordinary folder, which has never been rearranged, pays
// nothing and keeps the alphabetical order it arrived in.
func TestArrangeWithNoOrderIsUntouched(t *testing.T) {
	names := []string{"a", "b", "c"}
	got := Arrange(nil, names)
	if !reflect.DeepEqual(got, names) {
		t.Errorf("got %v, want %v", got, names)
	}
	got[0] = "changed"
	if names[0] != "a" {
		t.Error("Arrange handed back the caller's own slice")
	}
}

func TestParseOrderDropsBlanksAndComments(t *testing.T) {
	got := parseOrder("# what is this file\n\n  bank  \nwebsites/\n\n")
	want := []string{"bank", "websites/"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}
