package ui

import (
	"strings"
	"testing"

	"github.com/lvim-tech/keyforge/internal/passstore"
)

// TestModalPanesOwnTheKeyboard: the shell handles q, tab, h and l itself whenever the active view
// says it is not capturing, so a pane that means something else by those keys must say so. It did
// not, and the detail pane's own "q goes back" branch was unreachable — pressing it quit keyforge.
// The confirm dialog was worse: tab walked out of it while the view stayed in it, so returning to
// the tab later dropped the user into a delete confirmation raised minutes earlier.
func TestModalPanesOwnTheKeyboard(t *testing.T) {
	pass := &passView{}
	for _, m := range []storeMode{smForm, smMove, smFilter, smConfirm, smDetail} {
		pass.mode = m
		if !pass.capturesInput() {
			t.Errorf("passView mode %d lets the shell take the keys", m)
		}
	}
	pass.mode = smList
	if pass.capturesInput() {
		t.Error("the list must leave q and tab to the shell")
	}

	keys := &keysView{}
	for _, m := range []keysMode{kmNew, kmHost, kmDetail} {
		keys.mode = m
		if !keys.capturesInput() {
			t.Errorf("keysView mode %d lets the shell take the keys", m)
		}
	}
	keys.mode = kmList
	if keys.capturesInput() {
		t.Error("the list must leave q and tab to the shell")
	}
}

// TestEditFormCarriesTheWholeEntry: the edit form shows login and url, and the entry may hold far
// more. What it does not show, it must still write back — otherwise changing a password deletes the
// note, the otp: line and the recovery codes beside it.
func TestEditFormCarriesTheWholeEntry(t *testing.T) {
	body := "login: me\notp: JBSWY3DPEHPK3PXP\nnote: sheet in the drawer\n8f31-22aa\n"
	f := newPassFormReplace("websites/example.com/me", map[string]string{"login": "me"}, body, "")
	defer f.close()

	if f.origBody != body {
		t.Fatalf("the form did not keep the entry it was opened on: %q", f.origBody)
	}

	// What submit writes when the login is changed and nothing else is touched.
	out := passstore.SetFields(f.origBody, f.metaChanges("you", ""))
	for _, keep := range []string{"otp: JBSWY3DPEHPK3PXP", "note: sheet in the drawer", "8f31-22aa"} {
		if !strings.Contains(out, keep) {
			t.Errorf("an edit dropped %q\ngot:\n%s", keep, out)
		}
	}
	if !strings.Contains(out, "login: you") {
		t.Errorf("the edited field was not written: %s", out)
	}
}

// TestGeneratedEditClaimsItsEntropy: the entropy figures are asserted only when the value being
// written was generated here. Carrying an old entry's figures over to a typed password would put a
// number on it that nothing measured.
func TestGeneratedEditClaimsItsEntropy(t *testing.T) {
	f := newPassFormReplace("x", map[string]string{}, "", "")
	defer f.close()

	if _, ok := f.metaChanges("", "")["entropy"]; ok {
		t.Error("a typed value claimed an entropy")
	}
	f.bits = 70
	if got := f.metaChanges("", "")["entropy"]; got != "70 bits" {
		t.Errorf("entropy = %q", got)
	}
}
