package gpgkeys

import "testing"

// TestConfLine: gpg separates an option from its value with any whitespace and also accepts
// "name=value". Cutting on a single space missed a tab-formatted conf entirely — so the reader
// reported gpg's defaults, the "already in force" check never matched, and every launch rewrote the
// file and reloaded the agent, dropping every cached passphrase.
func TestConfLine(t *testing.T) {
	cases := []struct{ in, key, val string }{
		{"default-cache-ttl 600", "default-cache-ttl", "600"},
		{"default-cache-ttl\t600", "default-cache-ttl", "600"},
		{"  max-cache-ttl   7200  ", "max-cache-ttl", "7200"},
		{"default-cache-ttl=600", "default-cache-ttl", "600"},
		{"pinentry-program", "pinentry-program", ""},
		{"# default-cache-ttl 600", "", ""},
		{"   ", "", ""},
		{"", "", ""},
	}
	for _, c := range cases {
		key, val := confLine(c.in)
		if key != c.key || val != c.val {
			t.Errorf("confLine(%q) = (%q, %q), want (%q, %q)", c.in, key, val, c.key, c.val)
		}
	}
}

// TestShortGrip: the grips come from whatever the agent answered, and a short one used to panic the
// interface from inside the lock — the one moment the program must not fall off the screen.
func TestShortGrip(t *testing.T) {
	if got := shortGrip("0123456789ABCDEF"); got != "01234567" {
		t.Errorf("got %q", got)
	}
	for _, short := range []string{"", "abc", "12345678"} {
		if got := shortGrip(short); got != short {
			t.Errorf("shortGrip(%q) = %q", short, got)
		}
	}
}
