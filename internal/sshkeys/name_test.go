package sshkeys

import (
	"os"
	"testing"
)

// TestValidNameRefusesEscapes: the name typed into the new-key form becomes a path by a plain
// filepath.Join, so anything that climbs out of ~/.ssh writes the private half of a fresh key into
// a directory whose permissions nobody chose — while every message on screen says otherwise.
func TestValidNameRefusesEscapes(t *testing.T) {
	bad := []string{
		"",
		"   ",
		"../backup/key",
		"sub/key",
		".",
		"..",
		"-oProxyCommand=x",
	}
	for _, n := range bad {
		if err := ValidName(n); err == nil {
			t.Errorf("accepted %q", n)
		}
	}
}

func TestValidNameAcceptsOrdinaryNames(t *testing.T) {
	for _, n := range []string{"github-2026", "id_ed25519", "work.key", " padded "} {
		if err := ValidName(n); err != nil {
			t.Errorf("refused %q: %v", n, err)
		}
	}
}

// TestSpecValidate is the door the form actually goes through.
func TestSpecValidate(t *testing.T) {
	if err := (Spec{Name: "../x"}).Validate(); err == nil {
		t.Error("Spec.Validate accepted a name that leaves ~/.ssh")
	}
	if err := (Spec{Name: "ok"}).Validate(); err != nil {
		t.Errorf("Spec.Validate refused an ordinary name: %v", err)
	}
}

// TestKeyBlob: revoking matches the base64 body, not the whole line, because the comment differs
// from host to host.
func TestKeyBlob(t *testing.T) {
	if got := keyBlob("ssh-ed25519 AAAAC3Nz me@here"); got != "AAAAC3Nz" {
		t.Errorf("got %q", got)
	}
	if got := keyBlob("  ssh-rsa AAAAB3\n"); got != "AAAAB3" {
		t.Errorf("got %q", got)
	}
	if got := keyBlob("nonsense"); got != "" {
		t.Errorf("expected nothing for a line with no blob, got %q", got)
	}
}

// TestShellQuote: the revoke script is built here and run on the far side of an ssh, so a quote in
// the blob must not end the string it is inside.
func TestShellQuote(t *testing.T) {
	if got := shellQuote("a'b"); got != `'a'\''b'` {
		t.Errorf("got %s", got)
	}
	if got := shellQuote("plain"); got != "'plain'" {
		t.Errorf("got %s", got)
	}
}

// TestKnownHostsInCountsHashed: a machine you cannot name is still a machine your key may open, so
// hashed entries are counted rather than quietly dropped.
func TestKnownHostsInCountsHashed(t *testing.T) {
	dir := t.TempDir()
	write(t, dir+"/known_hosts", "# comment\n"+
		"host.one,alias ssh-ed25519 AAAA\n"+
		"|1|abcd|efgh ssh-rsa AAAA\n"+
		"host.one ssh-rsa AAAA\n")
	hosts, hashed := knownHostsIn(dir, map[string]bool{})
	if hashed != 1 {
		t.Errorf("hashed = %d, want 1", hashed)
	}
	want := map[string]bool{"host.one": true, "alias": true}
	if len(hosts) != len(want) {
		t.Fatalf("hosts = %v", hosts)
	}
	for _, h := range hosts {
		if !want[h] {
			t.Errorf("unexpected host %q", h)
		}
	}
}

// write is a test helper: a file with known contents, in a directory the test owns.
func write(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}
