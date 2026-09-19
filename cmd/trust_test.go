package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/SepehrRajabi/envvault/crypto"
)

// resetTrustFlags clears the package-global flags the trust command reads,
// so tests that set them directly don't leak state into one another.
func resetTrustFlags() {
	trustClear = false
	trustShow = false
	trustAlgorithm = ""
	trustRecipients = nil
}

func TestTrustCommandPreRegister(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	resetTrustFlags()
	t.Cleanup(resetTrustFlags)

	trustAlgorithm = "age-pubkey"
	trustRecipients = []string{"age1recipient"}

	vaultPath := filepath.Join(t.TempDir(), "prereg.env.vault")
	if err := trustCmd.RunE(trustCmd, []string{vaultPath}); err != nil {
		t.Fatalf("trust pre-register: %v", err)
	}

	record, ok, err := crypto.GetTrust(vaultPath)
	if err != nil || !ok {
		t.Fatalf("expected trust record, ok=%v err=%v", ok, err)
	}
	if record.Algorithm != "age-pubkey" {
		t.Fatalf("unexpected algorithm %q", record.Algorithm)
	}
	if len(record.Recipients) != 1 || record.Recipients[0] != "age1recipient" {
		t.Fatalf("unexpected recipients %v", record.Recipients)
	}
}

func TestTrustCommandClear(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	resetTrustFlags()
	t.Cleanup(resetTrustFlags)

	vaultPath := filepath.Join(t.TempDir(), "clear.env.vault")
	if err := crypto.SetTrust(vaultPath, crypto.TrustRecord{Algorithm: "aes256gcm-argon2id"}); err != nil {
		t.Fatalf("SetTrust: %v", err)
	}

	trustClear = true
	if err := trustCmd.RunE(trustCmd, []string{vaultPath}); err != nil {
		t.Fatalf("trust clear: %v", err)
	}

	if _, ok, _ := crypto.GetTrust(vaultPath); ok {
		t.Fatalf("expected trust record to be cleared")
	}
}

func TestTrustCommandPinFromFile(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	resetTrustFlags()
	t.Cleanup(resetTrustFlags)

	vault := newTestVault(t)
	vaultPath := filepath.Join(t.TempDir(), "pin.env.vault")
	if err := os.WriteFile(vaultPath, vault, 0600); err != nil {
		t.Fatalf("write vault: %v", err)
	}

	if err := trustCmd.RunE(trustCmd, []string{vaultPath}); err != nil {
		t.Fatalf("trust pin from file: %v", err)
	}

	record, ok, err := crypto.GetTrust(vaultPath)
	if err != nil || !ok {
		t.Fatalf("expected trust record, ok=%v err=%v", ok, err)
	}
	if record.Algorithm != "aes256gcm-argon2id" {
		t.Fatalf("unexpected algorithm %q", record.Algorithm)
	}
}

func TestTrustCommandShowMissingDoesNotError(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	resetTrustFlags()
	t.Cleanup(resetTrustFlags)

	trustShow = true
	vaultPath := filepath.Join(t.TempDir(), "missing.env.vault")
	if err := trustCmd.RunE(trustCmd, []string{vaultPath}); err != nil {
		t.Fatalf("trust show on missing pin should not error, got %v", err)
	}
}

func TestTrustCommandPinFromFileRejectsCorrupt(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	resetTrustFlags()
	t.Cleanup(resetTrustFlags)

	vaultPath := filepath.Join(t.TempDir(), "corrupt.env.vault")
	if err := os.WriteFile(vaultPath, []byte("not a vault"), 0600); err != nil {
		t.Fatalf("write file: %v", err)
	}

	if err := trustCmd.RunE(trustCmd, []string{vaultPath}); err == nil {
		t.Fatal("expected pinning a corrupt file to fail verification")
	}
}
