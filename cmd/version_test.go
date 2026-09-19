package cmd

import (
	"strings"
	"testing"
)

func TestVersionCommandPrintsVersion(t *testing.T) {
	out := captureStdout(t, func() {
		if err := versionCmd.RunE(versionCmd, nil); err != nil {
			t.Fatalf("version: %v", err)
		}
	})

	if !strings.Contains(out, fullVersion()) {
		t.Fatalf("expected output to contain %q, got %q", fullVersion(), out)
	}
}

func TestJoinVersionIncludesTagWhenSet(t *testing.T) {
	if got, want := joinVersion("0.0.3", "beta"), "0.0.3 beta"; got != want {
		t.Fatalf("joinVersion() = %q, want %q", got, want)
	}
}

func TestJoinVersionOmitsEmptyTag(t *testing.T) {
	if got, want := joinVersion("0.0.3", ""), "0.0.3"; got != want {
		t.Fatalf("joinVersion() = %q, want %q", got, want)
	}
}
