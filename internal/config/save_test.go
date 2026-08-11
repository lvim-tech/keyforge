package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestSaveKeepsKeysItDoesNotKnow(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	if err := os.MkdirAll(filepath.Join(dir, "keyforge"), 0o700); err != nil {
		t.Fatal(err)
	}
	// A key from a newer keyforge, or from the user's own hand. Losing it silently is the
	// failure this test exists to prevent.
	const before = `{"password_length": 20, "something_else": {"kept": true}}`
	if err := os.WriteFile(Path(), []byte(before), 0o600); err != nil {
		t.Fatal(err)
	}

	c := Default()
	c.PasswordLength = 33
	if err := Save(c); err != nil {
		t.Fatal(err)
	}

	raw, err := os.ReadFile(Path())
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]json.RawMessage
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if _, ok := got["something_else"]; !ok {
		t.Errorf("an unknown key was deleted:\n%s", raw)
	}
	var n int
	_ = json.Unmarshal(got["password_length"], &n)
	if n != 33 {
		t.Errorf("password_length = %d, want 33", n)
	}
}
