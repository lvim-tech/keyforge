package audit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestAuthorizedKeysOptionsPrefix: a line may begin with options — command="…", from="…",
// no-pty — and the key type is then the SECOND field. Reading the first one would report every
// restricted key as a malformed line, which is the loudest finding this file can produce.
func TestAuthorizedKeysOptionsPrefix(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, "authorized_keys"),
		"# a comment\n"+
			"\n"+
			"ssh-ed25519 AAAAC3Nz me@here\n"+
			`command="/usr/bin/true",no-pty ssh-rsa AAAAB3 backup@there`+"\n")

	out := authorizedKeys(dir, false)
	for _, f := range out {
		if strings.Contains(f.Message, "unknown key type") {
			t.Errorf("a valid line was reported as malformed: %+v", f)
		}
	}
	if !hasCount(out, "2 keys can log into this account") {
		t.Errorf("the key count is wrong: %+v", out)
	}
}

// TestAuthorizedKeysFlagsAMalformedLine: sshd skips a bad line without a word, so key
// authentication has quietly not worked for however long the typo has been there.
func TestAuthorizedKeysFlagsAMalformedLine(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, "authorized_keys"), "ssh-ed2551 AAAAC3Nz typo@here\n")

	out := authorizedKeys(dir, false)
	found := false
	for _, f := range out {
		if strings.Contains(f.Message, "unknown key type") {
			found = true
			if f.Severity != High {
				t.Errorf("a silently skipped key is not a low-severity fact: %+v", f)
			}
			if !strings.HasSuffix(f.Subject, ":1") {
				t.Errorf("the line number is wrong: %q", f.Subject)
			}
		}
	}
	if !found {
		t.Errorf("the malformed line was not reported: %+v", out)
	}
}

// TestAuthorizedKeysAbsent: no file is not a finding. An account that nothing can log into with a
// key is the ordinary case on a workstation.
func TestAuthorizedKeysAbsent(t *testing.T) {
	if out := authorizedKeys(t.TempDir(), false); len(out) != 0 {
		t.Errorf("a missing file produced findings: %+v", out)
	}
}

func hasCount(out []Finding, want string) bool {
	for _, f := range out {
		if f.Message == want {
			return true
		}
	}
	return false
}

func write(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}
