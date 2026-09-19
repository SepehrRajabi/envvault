package cmd

import (
	"encoding/json"
	"strings"
	"testing"
)

func resetAlgorithmsFlags() {
	verboseAlgorithms = false
	onlySecureAlgorithms = false
	jsonAlgorithms = false
}

func TestAlgorithmsCommandDefaultListsKnownAlgorithms(t *testing.T) {
	resetAlgorithmsFlags()
	t.Cleanup(resetAlgorithmsFlags)

	out := captureStdout(t, func() {
		if err := algCmd.RunE(algCmd, nil); err != nil {
			t.Fatalf("algorithms: %v", err)
		}
	})

	for _, want := range []string{"aes256gcm-argon2id", "age-pubkey", "shamir-aes256gcm"} {
		if !strings.Contains(out, want) {
			t.Fatalf("expected output to list %q, got:\n%s", want, out)
		}
	}
}

func TestAlgorithmsCommandSecureOnlyExcludesInsecure(t *testing.T) {
	resetAlgorithmsFlags()
	t.Cleanup(resetAlgorithmsFlags)
	onlySecureAlgorithms = true

	out := captureStdout(t, func() {
		if err := algCmd.RunE(algCmd, nil); err != nil {
			t.Fatalf("algorithms --secure: %v", err)
		}
	})

	// "chacha20" (raw, unauthenticated) is the only algorithm registered
	// as insecure; --secure must exclude it while keeping the rest.
	if strings.Contains(out, "  chacha20\n") || strings.Contains(out, "* chacha20\n") {
		t.Fatalf("expected --secure to exclude the insecure chacha20 algorithm, got:\n%s", out)
	}
	if !strings.Contains(out, "aes256gcm-argon2id") {
		t.Fatalf("expected --secure to still include secure algorithms, got:\n%s", out)
	}
}

func TestAlgorithmsCommandJSONOutput(t *testing.T) {
	resetAlgorithmsFlags()
	t.Cleanup(resetAlgorithmsFlags)
	jsonAlgorithms = true

	out := captureStdout(t, func() {
		if err := algCmd.RunE(algCmd, nil); err != nil {
			t.Fatalf("algorithms --json: %v", err)
		}
	})

	var entries []algorithmJSONEntry
	if err := json.Unmarshal([]byte(out), &entries); err != nil {
		t.Fatalf("expected valid JSON, got error %v for:\n%s", err, out)
	}
	if len(entries) == 0 {
		t.Fatal("expected at least one algorithm entry")
	}

	foundDefault := false
	for _, e := range entries {
		if e.Default {
			foundDefault = true
		}
	}
	if !foundDefault {
		t.Fatal("expected exactly one algorithm to be marked default")
	}
}
