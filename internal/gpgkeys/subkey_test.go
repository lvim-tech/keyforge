package gpgkeys

import "testing"

// TestSubkeyExpiryWins: the encryption subkey is what stops `pass`, so its date is the one the
// interface must show — the primary's alone said "2030" while the store died in 2027.
func TestSubkeyExpiryWins(t *testing.T) {
	const colons = `sec:u:4096:1:AAAABBBBCCCCDDDD:1700000000:1900000000::u:::scESC::::::23::0:
uid:u::::1700000000::HASH::Real Name <r@t.invalid>::::::::::0:
ssb:u:4096:1:1111222233334444:1700000000:1800000000:::::e::::::23:
`
	keys := parseKeys(colons)
	if len(keys) != 1 {
		t.Fatalf("parsed %d keys, want 1", len(keys))
	}
	k := keys[0]
	if k.SubkeyExpires.IsZero() {
		t.Fatal("the encryption subkey's expiry was not read")
	}
	if !k.ExpiryIsSubkey {
		t.Error("the sooner date came from the subkey and was not marked as such")
	}
	if got := k.Expires.Unix(); got != 1800000000 {
		t.Errorf("Expires = %d, want the subkey's 1800000000", got)
	}
}
