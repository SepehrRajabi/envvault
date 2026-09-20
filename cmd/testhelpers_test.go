package cmd

import (
	"bytes"
	"io"
	"os"
	"testing"
)

// captureStdout redirects os.Stdout for the duration of fn and returns
// everything written to it. Several commands (algorithms, inspect, history,
// keygen, status...) only expose their result via stdout, so tests need this
// to assert on output instead of just the returned error.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	orig := os.Stdout
	os.Stdout = w
	defer func() { os.Stdout = orig }()

	fn()

	w.Close()
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r); err != nil {
		t.Fatalf("reading captured stdout: %v", err)
	}
	return buf.String()
}

// captureStderr is captureStdout's counterpart for commands (and internal
// helpers like configureHistoryBackend) that report warnings on stderr.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	orig := os.Stderr
	os.Stderr = w
	defer func() { os.Stderr = orig }()

	fn()

	w.Close()
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r); err != nil {
		t.Fatalf("reading captured stderr: %v", err)
	}
	return buf.String()
}
