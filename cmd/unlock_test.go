package cmd

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/SepehrRajabi/envvault/crypto"
)

func resetUnlockFlags() {
	unlockOutput = ""
	requestAccess = false
	quorumShare = ""
}

func TestUnlockCommandDefaultOutputPath(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("ENVVAULT_PASSWORD", "password123")
	resetUnlockFlags()
	t.Cleanup(resetUnlockFlags)

	dir := t.TempDir()
	vaultPath := filepath.Join(dir, "secret.env.vault")
	if err := os.WriteFile(vaultPath, newTestVault(t), 0600); err != nil {
		t.Fatalf("write vault: %v", err)
	}

	if err := unlockCmd.RunE(unlockCmd, []string{vaultPath}); err != nil {
		t.Fatalf("unlock: %v", err)
	}

	outPath := filepath.Join(dir, "secret.env")
	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("expected default output file %s: %v", outPath, err)
	}
	if string(data) != "secret=very_secret\n" {
		t.Fatalf("unexpected decrypted content: %q", data)
	}
}

func TestUnlockCommandCustomOutputPath(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("ENVVAULT_PASSWORD", "password123")
	resetUnlockFlags()
	t.Cleanup(resetUnlockFlags)

	dir := t.TempDir()
	vaultPath := filepath.Join(dir, "secret.env.vault")
	if err := os.WriteFile(vaultPath, newTestVault(t), 0600); err != nil {
		t.Fatalf("write vault: %v", err)
	}

	outPath := filepath.Join(dir, "custom.env")
	unlockOutput = outPath

	if err := unlockCmd.RunE(unlockCmd, []string{vaultPath}); err != nil {
		t.Fatalf("unlock: %v", err)
	}

	if _, err := os.Stat(outPath); err != nil {
		t.Fatalf("expected custom output file: %v", err)
	}
}

func TestUnlockCommandHasDecryptAlias(t *testing.T) {
	if !slices.Contains(unlockCmd.Aliases, "decrypt") {
		t.Fatalf("expected unlock command to have 'decrypt' alias, got %v", unlockCmd.Aliases)
	}
}

func TestUnlockCommandShamirQuorum(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	resetUnlockFlags()
	t.Cleanup(resetUnlockFlags)

	provider := &crypto.ShamirAESGCMProvider{
		ID: "shamir-aes256gcm", Time: 3, Memory: 64 * 1024, Threads: 4,
		SaltLen: 32, NonceLen: 12, Shares: 3, Threshold: 2,
	}
	vault, err := crypto.Encrypt([]byte("secret=quorum\n"), []byte("shamir-secret-password"), provider)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	shares := provider.GeneratedShares()
	if len(shares) != 3 {
		t.Fatalf("expected 3 generated shares, got %d", len(shares))
	}

	dir := t.TempDir()
	vaultPath := filepath.Join(dir, "quorum.env.vault")
	if err := os.WriteFile(vaultPath, vault, 0600); err != nil {
		t.Fatalf("write vault: %v", err)
	}

	requestAccess = true

	// First share: below threshold, should not decrypt yet.
	quorumShare = shares[0]
	if err := unlockCmd.RunE(unlockCmd, []string{vaultPath}); err != nil {
		t.Fatalf("submit first share: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "quorum.env")); err == nil {
		t.Fatal("expected no output file before threshold is reached")
	}

	// Second (distinct) share reaches threshold and decrypts.
	quorumShare = shares[1]
	if err := unlockCmd.RunE(unlockCmd, []string{vaultPath}); err != nil {
		t.Fatalf("submit second share: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(dir, "quorum.env"))
	if err != nil {
		t.Fatalf("expected quorum decryption to produce output file: %v", err)
	}
	if string(data) != "secret=quorum\n" {
		t.Fatalf("unexpected decrypted content: %q", data)
	}
}
