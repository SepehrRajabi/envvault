package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func resetShamirFlags() {
	shamirSplitShares = 5
	shamirSplitThreshold = 3
	shamirSplitOutDir = ""
}

func TestShamirSplitAndCombineRoundTrip(t *testing.T) {
	resetShamirFlags()
	t.Cleanup(resetShamirFlags)
	shamirSplitShares = 3
	shamirSplitThreshold = 2

	var shares []string
	out := captureStdout(t, func() {
		if err := shamirSplitCmd.RunE(shamirSplitCmd, []string{"my-shamir-secret"}); err != nil {
			t.Fatalf("shamir split: %v", err)
		}
	})
	for _, line := range strings.Split(out, "\n") {
		if idx := strings.Index(line, "share "); idx != -1 {
			if colon := strings.Index(line, ": "); colon != -1 {
				shares = append(shares, strings.TrimSpace(line[colon+2:]))
			}
		}
	}
	if len(shares) != 3 {
		t.Fatalf("expected 3 shares parsed from output, got %d from:\n%s", len(shares), out)
	}

	combined := captureStdout(t, func() {
		if err := shamirCombineCmd.RunE(shamirCombineCmd, shares[:2]); err != nil {
			t.Fatalf("shamir combine: %v", err)
		}
	})
	if strings.TrimSpace(combined) != "my-shamir-secret" {
		t.Fatalf("expected recovered secret, got %q", combined)
	}
}

func TestShamirCombineInsufficientSharesFails(t *testing.T) {
	resetShamirFlags()
	t.Cleanup(resetShamirFlags)
	shamirSplitShares = 3
	shamirSplitThreshold = 2

	out := captureStdout(t, func() {
		if err := shamirSplitCmd.RunE(shamirSplitCmd, []string{"another-secret"}); err != nil {
			t.Fatalf("shamir split: %v", err)
		}
	})

	var shares []string
	for _, line := range strings.Split(out, "\n") {
		if colon := strings.Index(line, ": "); colon != -1 && strings.Contains(line, "share ") {
			shares = append(shares, strings.TrimSpace(line[colon+2:]))
		}
	}
	if len(shares) < 1 {
		t.Fatalf("expected at least one share parsed, got output:\n%s", out)
	}

	if err := shamirCombineCmd.RunE(shamirCombineCmd, []string{shares[0]}); err == nil {
		t.Fatal("expected combine with a single share to fail (need at least 2)")
	}
}

func TestShamirSplitOutDirWritesShareFiles(t *testing.T) {
	resetShamirFlags()
	t.Cleanup(resetShamirFlags)
	shamirSplitShares = 3
	shamirSplitThreshold = 2
	dir := t.TempDir()
	shamirSplitOutDir = dir

	if err := shamirSplitCmd.RunE(shamirSplitCmd, []string{"file-secret"}); err != nil {
		t.Fatalf("shamir split: %v", err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("reading out dir: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("expected 3 share files, got %d", len(entries))
	}
	if _, err := os.Stat(filepath.Join(dir, "shamir-share-1.txt")); err != nil {
		t.Fatalf("expected named share file: %v", err)
	}
}
