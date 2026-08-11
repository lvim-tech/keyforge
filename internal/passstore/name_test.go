package passstore

import "testing"

// TestValidNameRefusesTraversal: an entry name becomes a path under the store, so a name that
// climbs out of it writes a GPG file wherever the caller's imagination reaches.
func TestValidNameRefusesTraversal(t *testing.T) {
	bad := []string{
		"../outside",
		"a/../../outside",
		"/absolute",
		"",
		"   ",
		"trailing/",
	}
	for _, n := range bad {
		if err := ValidName(n); err == nil {
			t.Errorf("accepted %q", n)
		}
	}
	good := []string{"websites/example.com/user", "single", "a/b/c"}
	for _, n := range good {
		if err := ValidName(n); err != nil {
			t.Errorf("refused %q: %v", n, err)
		}
	}
}
