package passstore

import (
	"strings"
	"testing"
)

// TestSetFieldsKeepsEverythingElse is the regression test for the defect the whole Body/SetFields
// pair exists to close: editing an entry used to rebuild it from the two fields the form shows, so
// a note, an otp: secret and a block of recovery codes were deleted by a routine password change.
func TestSetFieldsKeepsEverythingElse(t *testing.T) {
	body := "login: me\n" +
		"url: https://example.com\n" +
		"otp: JBSWY3DPEHPK3PXP\n" +
		"note: the printed sheet is in the drawer\n" +
		"8f31-22aa-0c7e\n" // a recovery code: no colon, so no field can represent it

	out := SetFields(body, map[string]string{"login": "someone-else", "url": "https://example.org"})

	for _, keep := range []string{
		"otp: JBSWY3DPEHPK3PXP",
		"note: the printed sheet is in the drawer",
		"8f31-22aa-0c7e",
	} {
		if !strings.Contains(out, keep) {
			t.Errorf("SetFields dropped %q\ngot:\n%s", keep, out)
		}
	}
	if !strings.Contains(out, "login: someone-else") || strings.Contains(out, "login: me") {
		t.Errorf("login was not replaced\ngot:\n%s", out)
	}
	if !strings.Contains(out, "url: https://example.org") {
		t.Errorf("url was not replaced\ngot:\n%s", out)
	}
}

// TestSetFieldsKeepsOrder: the entry is rewritten in place, so a git-backed store shows a one-line
// diff rather than a reordering of everything.
func TestSetFieldsKeepsOrder(t *testing.T) {
	body := "url: https://example.com\nnote: second\nlogin: me\n"
	out := SetFields(body, map[string]string{"login": "you"})
	want := "url: https://example.com\nnote: second\nlogin: you\n"
	if out != want {
		t.Errorf("got:\n%q\nwant:\n%q", out, want)
	}
}

// TestSetFieldsRemovesClearedField: emptying the login box in the form means the entry no longer
// claims a login, which is different from leaving the old one there.
func TestSetFieldsRemovesClearedField(t *testing.T) {
	out := SetFields("login: me\nurl: https://example.com\n", map[string]string{"login": ""})
	if strings.Contains(out, "login") {
		t.Errorf("the cleared field survived: %q", out)
	}
	if !strings.Contains(out, "url: https://example.com") {
		t.Errorf("the untouched field went with it: %q", out)
	}
}

// TestSetFieldsAppendsWhatIsNotThere: an entry that never had a url gets one.
func TestSetFieldsAppendsWhatIsNotThere(t *testing.T) {
	out := SetFields("login: me\n", map[string]string{"url": "https://example.com"})
	if !strings.HasSuffix(out, "url: https://example.com\n") {
		t.Errorf("the new field was not appended: %q", out)
	}
}

// TestSetFieldsOnEmptyBody covers the entry whose metadata could not be read back: the form then
// writes only what it holds, which is the documented fallback rather than a crash.
func TestSetFieldsOnEmptyBody(t *testing.T) {
	if got := SetFields("", map[string]string{"login": "", "url": ""}); got != "" {
		t.Errorf("expected nothing, got %q", got)
	}
	if got := SetFields("", map[string]string{"login": "me"}); got != "login: me\n" {
		t.Errorf("got %q", got)
	}
}

// TestSetFieldsRefusesToForgeALine: a newline inside a value would end the field and start another,
// which is how a value becomes a field somebody else reads. Same guard renderMeta has.
func TestSetFieldsRefusesToForgeALine(t *testing.T) {
	out := SetFields("login: me\n", map[string]string{"login": "me\notp: stolen"})
	if strings.Count(out, "\n") != 1 {
		t.Errorf("a value forged an extra line: %q", out)
	}
}

func TestRenderMetaRefusesToForgeALine(t *testing.T) {
	out := renderMeta(map[string]string{"login": "me\nurl: elsewhere"})
	if strings.Count(out, "\n") != 1 {
		t.Errorf("a value forged an extra line: %q", out)
	}
}

// TestRenderMetaIsDeterministic: same input, same file — otherwise a git-backed store shows
// reordered noise on every write.
func TestRenderMetaIsDeterministic(t *testing.T) {
	m := map[string]string{"url": "u", "login": "l", "entropy": "70 bits"}
	first := renderMeta(m)
	for i := 0; i < 20; i++ {
		if renderMeta(m) != first {
			t.Fatal("renderMeta is not stable across calls")
		}
	}
	if first != "entropy: 70 bits\nlogin: l\nurl: u\n" {
		t.Errorf("got %q", first)
	}
}

// TestRenderMetaDropsEmpty: a field with no value is not a field.
func TestRenderMetaDropsEmpty(t *testing.T) {
	if got := renderMeta(map[string]string{"login": "  ", "url": "u"}); got != "url: u\n" {
		t.Errorf("got %q", got)
	}
}

func TestParseFields(t *testing.T) {
	got := parseFields("login: me\nnot a field\nurl: https://example.com\n: novalue\nempty:\n")
	if len(got) != 2 || got["login"] != "me" || got["url"] != "https://example.com" {
		t.Errorf("got %v", got)
	}
}
