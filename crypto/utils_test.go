package crypto

import (
	"os"
	"testing"
)

// withStdin replaces os.Stdin with a pipe carrying input for the test.
func withStdin(t *testing.T, input string) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.WriteString(input); err != nil {
		t.Fatal(err)
	}
	w.Close()
	old := os.Stdin
	os.Stdin = r
	t.Cleanup(func() { os.Stdin = old; r.Close() })
}

func TestPipedPasswordKeepsWhitespace(t *testing.T) {
	t.Setenv("ENVVAULT_PASSWORD", "")
	withStdin(t, "correct horse\tbattery staple\n")
	got, err := GetPassword("")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "correct horse\tbattery staple" {
		t.Fatalf("password truncated or altered: %q", got)
	}
}

func TestPipedPasswordsReadSequentially(t *testing.T) {
	t.Setenv("ENVVAULT_PASSWORD", "")
	withStdin(t, "first pass\r\nsecond pass")
	a, err := GetPassword("")
	if err != nil || string(a) != "first pass" {
		t.Fatalf("first = %q, %v", a, err)
	}
	b, err := GetPassword("")
	if err != nil || string(b) != "second pass" {
		t.Fatalf("second (no trailing newline) = %q, %v", b, err)
	}
	if _, err := GetPassword(""); err == nil {
		t.Fatal("expected error at EOF")
	}
}

func TestPipedEmptyPasswordRejected(t *testing.T) {
	t.Setenv("ENVVAULT_PASSWORD", "")
	withStdin(t, "\n")
	if _, err := GetPassword(""); err == nil {
		t.Fatal("expected empty piped password to be rejected")
	}
}
