package sys

import "testing"

func TestDropThroughKeepsOnlyWhatFollows(t *testing.T) {
	s, err := NewSecret(64)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.Append([]byte("hunter2\nurl: example.invalid\nuser: bo"))
	s.DropThrough('\n')

	var got string
	s.Use(func(v string) { got = v })
	if want := "url: example.invalid\nuser: bo"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
	// The password must be gone from the buffer, not merely unreturned.
	for i := 0; i < len(s.buf); i++ {
		if s.buf[i] == 'h' && i+7 <= len(s.buf) && string(s.buf[i:i+7]) == "hunter2" {
			t.Fatal("the password is still in the locked buffer")
		}
	}
}

func TestDropThroughWithNoSeparatorEmpties(t *testing.T) {
	s, err := NewSecret(64)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.Append([]byte("only-a-password"))
	s.DropThrough('\n')
	if !s.Empty() {
		t.Fatal("a buffer that was all password did not end up empty")
	}
}
