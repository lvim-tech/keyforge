package gpgkeys

import (
	"testing"
	"time"
)

// A real keyring's shape: the primary signs and certifies, a subkey does the encrypting. Its
// capability field reads "scESC" — lowercase for what the primary itself does, uppercase for the
// sum over the whole keyblock. Matching that field without regard to case picks the primary, whose
// passphrase is not the one `pass` asks for, and on a keyring with an offline primary the answer
// comes out backwards. This is the case that must not regress.
// Copied from real `gpg --with-colons --with-keygrip` output rather than written by hand: the
// capability column is field 12, and counting the empty fields up to it by eye is how a parser
// ends up reading the one beside it.
const colonsPrimarySignsSubkeyEncrypts = `sec:u:4096:1:C140DA4AE96241C4:1673346000:::u:::scESC:::+:::23::0:
fpr:::::::::F3A8369FAA2236219AA76D62C140DA4AE96241C4:
grp:::::::::F7F96A359A4C6E8558B034F1649A54C90FAB20E4:
uid:u::::1673346000::ABCDEF::lvim-tech <lvim-tech@example.org>::::::::::0:
ssb:u:4096:1:B23AC77346F2B132:1673346000::::::e:::+:::23:
grp:::::::::1800DCD5D471E3DB851D2C19CFE9E1BE2A0D5FDE:
`

func TestEncryptionKeygripPrefersTheSubkeyThatDecrypts(t *testing.T) {
	grip, id := parseEncryptionKeygrip(colonsPrimarySignsSubkeyEncrypts)
	if want := "1800DCD5D471E3DB851D2C19CFE9E1BE2A0D5FDE"; grip != want {
		t.Errorf("keygrip = %q, want the subkey %q (the uppercase letters in scESC are not the primary's own capability)", grip, want)
	}
	if want := "B23AC77346F2B132"; id != want {
		t.Errorf("key id = %q, want %q", id, want)
	}
}

// A keyblock with no encryption subkey at all still has to produce something, or the audit reports
// "could not check" for a key it is perfectly able to check.
func TestEncryptionKeygripFallsBackToThePrimary(t *testing.T) {
	const colons = `sec:u:4096:1:AAAABBBBCCCCDDDD:1673346000:::u:::scSC:::+:::23::0:
grp:::::::::1111111111111111111111111111111111111111:
`
	grip, _ := parseEncryptionKeygrip(colons)
	if want := "1111111111111111111111111111111111111111"; grip != want {
		t.Errorf("keygrip = %q, want %q", grip, want)
	}
}

func TestEncryptionKeygripOnNothing(t *testing.T) {
	if grip, id := parseEncryptionKeygrip(""); grip != "" || id != "" {
		t.Errorf("empty output yields %q/%q", grip, id)
	}
}

// The agent's reply is positional and its columns are easy to shift by one. P/C is the whole answer
// to "is this protected"; the column before it says whether the passphrase is cached right now.
func TestParseKeyInfo(t *testing.T) {
	const out = `S KEYINFO F7F96A359A4C6E8558B034F1649A54C90FAB20E4 D - - - P - - -
S KEYINFO 0C88095C45220ACD3E340102F1581CCD20EA7962 D - - 1 C - 600 -
S KEYINFO DAD86D411329C440B47B2F2BA5C3BD5E3344AFE6 D - - - X - - -
OK
`
	got := parseKeyInfo(out)
	if len(got) != 3 {
		t.Fatalf("parsed %d keys, want 3", len(got))
	}

	p := got["F7F96A359A4C6E8558B034F1649A54C90FAB20E4"]
	if !p.Known || !p.Protected || p.Cached {
		t.Errorf("P with no cache = %+v", p)
	}

	p = got["0C88095C45220ACD3E340102F1581CCD20EA7962"]
	if !p.Known || p.Protected {
		t.Errorf("C must mean NO passphrase: %+v", p)
	}
	if !p.Cached {
		t.Errorf("the cache column is 1 but Cached=false: %+v", p)
	}
	if p.TTL != 600*time.Second {
		t.Errorf("TTL = %v, want 600s", p.TTL)
	}

	// An answer the agent would not give is not an answer. Reporting it as "protected" would be
	// exactly the false reassurance this package exists to avoid.
	if p := got["DAD86D411329C440B47B2F2BA5C3BD5E3344AFE6"]; p.Known {
		t.Errorf("unknown protection is reported as known: %+v", p)
	}
}
