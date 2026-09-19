package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/SepehrRajabi/envvault/crypto"
)

func resetLockFlags() {
	algorithm = ""
	listAlgs = false
	allowWeak = false
	allowInsecure = false
	recipient = nil
	shamirShares = 5
	shamirThreshold = 3
	shamirSharesDir = ""
	noTrust = false
}

func TestLockCommandPasswordRoundTrip(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("ENVVAULT_PASSWORD", "correct-horse-battery-staple-42!")
	resetLockFlags()
	t.Cleanup(resetLockFlags)

	dir := t.TempDir()
	envPath := filepath.Join(dir, ".env")
	if err := os.WriteFile(envPath, []byte("KEY=value\n"), 0600); err != nil {
		t.Fatalf("write env file: %v", err)
	}

	if err := lockCmd.RunE(lockCmd, []string{envPath}); err != nil {
		t.Fatalf("lock: %v", err)
	}

	vaultPath := envPath + ".vault"
	data, err := os.ReadFile(vaultPath)
	if err != nil {
		t.Fatalf("expected vault file to be created: %v", err)
	}

	plaintext, err := crypto.Decrypt(data, []byte("correct-horse-battery-staple-42!"), nil)
	if err != nil {
		t.Fatalf("decrypt round trip: %v", err)
	}
	if string(plaintext) != "KEY=value\n" {
		t.Fatalf("unexpected plaintext: %q", plaintext)
	}

	// lock pins trust by default.
	record, ok, err := crypto.GetTrust(vaultPath)
	if err != nil || !ok {
		t.Fatalf("expected trust pin after lock, ok=%v err=%v", ok, err)
	}
	if record.Algorithm != "aes256gcm-argon2id" {
		t.Fatalf("unexpected pinned algorithm %q", record.Algorithm)
	}
}

func TestLockCommandNoTrustSkipsPin(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("ENVVAULT_PASSWORD", "correct-horse-battery-staple-42!")
	resetLockFlags()
	t.Cleanup(resetLockFlags)
	noTrust = true

	dir := t.TempDir()
	envPath := filepath.Join(dir, ".env")
	if err := os.WriteFile(envPath, []byte("KEY=value\n"), 0600); err != nil {
		t.Fatalf("write env file: %v", err)
	}

	if err := lockCmd.RunE(lockCmd, []string{envPath}); err != nil {
		t.Fatalf("lock: %v", err)
	}

	if _, ok, _ := crypto.GetTrust(envPath + ".vault"); ok {
		t.Fatalf("expected no trust pin when --no-trust is set")
	}
}

func TestLockCommandRejectsWeakPassword(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("ENVVAULT_PASSWORD", "abc123")
	resetLockFlags()
	t.Cleanup(resetLockFlags)

	dir := t.TempDir()
	envPath := filepath.Join(dir, ".env")
	if err := os.WriteFile(envPath, []byte("KEY=value\n"), 0600); err != nil {
		t.Fatalf("write env file: %v", err)
	}

	if err := lockCmd.RunE(lockCmd, []string{envPath}); err == nil {
		t.Fatal("expected weak password to be rejected")
	}
	if _, err := os.Stat(envPath + ".vault"); err == nil {
		t.Fatal("expected no vault file to be written for a rejected password")
	}
}

func TestLockCommandAllowWeakBypassesStrengthCheck(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("ENVVAULT_PASSWORD", "abc123")
	resetLockFlags()
	t.Cleanup(resetLockFlags)
	allowWeak = true

	dir := t.TempDir()
	envPath := filepath.Join(dir, ".env")
	if err := os.WriteFile(envPath, []byte("KEY=value\n"), 0600); err != nil {
		t.Fatalf("write env file: %v", err)
	}

	if err := lockCmd.RunE(lockCmd, []string{envPath}); err != nil {
		t.Fatalf("expected --allow-weak to bypass strength check, got %v", err)
	}
}

func TestLockCommandRecipientModeRejectsMismatchedAlgorithm(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	resetLockFlags()
	t.Cleanup(resetLockFlags)
	recipient = []string{"age1qz2wyfr4t8dp3v3whgg8w4jslgqmauawf5vd5nzr0eslc5qq0plfghegjnl"}
	algorithm = "aes256gcm-argon2id"

	dir := t.TempDir()
	envPath := filepath.Join(dir, ".env")
	if err := os.WriteFile(envPath, []byte("KEY=value\n"), 0600); err != nil {
		t.Fatalf("write env file: %v", err)
	}

	if err := lockCmd.RunE(lockCmd, []string{envPath}); err == nil {
		t.Fatal("expected mismatched --recipient/--algorithm combination to be rejected")
	}
}

func TestLockCommandInsecureAlgorithmRejectedByDefault(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("ENVVAULT_PASSWORD", "correct-horse-battery-staple-42!")
	resetLockFlags()
	t.Cleanup(resetLockFlags)
	algorithm = "chacha20"

	dir := t.TempDir()
	envPath := filepath.Join(dir, ".env")
	if err := os.WriteFile(envPath, []byte("KEY=value\n"), 0600); err != nil {
		t.Fatalf("write env file: %v", err)
	}

	if err := lockCmd.RunE(lockCmd, []string{envPath}); err == nil {
		t.Fatal("expected insecure algorithm to be rejected without --allow-insecure")
	}
}

func TestLockCommandShamirInvalidThreshold(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("ENVVAULT_PASSWORD", "correct-horse-battery-staple-42!")
	resetLockFlags()
	t.Cleanup(resetLockFlags)
	algorithm = "shamir-aes256gcm"
	shamirShares = 2
	shamirThreshold = 5 // shares < threshold

	dir := t.TempDir()
	envPath := filepath.Join(dir, ".env")
	if err := os.WriteFile(envPath, []byte("KEY=value\n"), 0600); err != nil {
		t.Fatalf("write env file: %v", err)
	}

	if err := lockCmd.RunE(lockCmd, []string{envPath}); err == nil {
		t.Fatal("expected --shares < --threshold to be rejected")
	}
}

func TestLockCommandSharesDirWritesShareFiles(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("ENVVAULT_PASSWORD", "correct-horse-battery-staple-42!")
	resetLockFlags()
	t.Cleanup(resetLockFlags)
	algorithm = "shamir-aes256gcm"
	shamirShares = 3
	shamirThreshold = 2
	sharesDir := t.TempDir()
	shamirSharesDir = sharesDir

	dir := t.TempDir()
	envPath := filepath.Join(dir, ".env")
	if err := os.WriteFile(envPath, []byte("KEY=value\n"), 0600); err != nil {
		t.Fatalf("write env file: %v", err)
	}

	if err := lockCmd.RunE(lockCmd, []string{envPath}); err != nil {
		t.Fatalf("lock with shamir: %v", err)
	}

	entries, err := os.ReadDir(sharesDir)
	if err != nil {
		t.Fatalf("reading shares dir: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("expected 3 share files, got %d", len(entries))
	}
}
