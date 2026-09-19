package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/SepehrRajabi/envvault/crypto"
)

func resetMigrateFlags() {
	from = ""
	to = ""
	output = ""
}

func TestMigrateCommandChangesAlgorithmInPlace(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("ENVVAULT_PASSWORD", "correct-horse-battery-staple-42!")
	resetMigrateFlags()
	t.Cleanup(resetMigrateFlags)

	provider, err := crypto.GetProvider("aes256gcm-argon2id")
	if err != nil {
		t.Fatalf("GetProvider: %v", err)
	}
	vault, err := crypto.Encrypt([]byte("KEY=value\n"), []byte("correct-horse-battery-staple-42!"), provider)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	dir := t.TempDir()
	vaultPath := filepath.Join(dir, "v.env.vault")
	if err := os.WriteFile(vaultPath, vault, 0600); err != nil {
		t.Fatalf("write vault: %v", err)
	}

	to = "chacha20poly1305"

	if err := migrateCmd.RunE(migrateCmd, []string{vaultPath}); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	after, err := os.ReadFile(vaultPath)
	if err != nil {
		t.Fatalf("read vault after migrate: %v", err)
	}

	alg, err := crypto.PeekAlgorithm(after)
	if err != nil {
		t.Fatalf("PeekAlgorithm: %v", err)
	}
	if alg != "chacha20poly1305" {
		t.Fatalf("expected algorithm chacha20poly1305 after migrate, got %q", alg)
	}

	plaintext, err := crypto.Decrypt(after, []byte("correct-horse-battery-staple-42!"), nil)
	if err != nil {
		t.Fatalf("decrypt migrated vault: %v", err)
	}
	if string(plaintext) != "KEY=value\n" {
		t.Fatalf("unexpected plaintext after migrate: %q", plaintext)
	}
}

func TestMigrateCommandOutputFlagLeavesOriginalUntouched(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("ENVVAULT_PASSWORD", "correct-horse-battery-staple-42!")
	resetMigrateFlags()
	t.Cleanup(resetMigrateFlags)

	provider, err := crypto.GetProvider("aes256gcm-argon2id")
	if err != nil {
		t.Fatalf("GetProvider: %v", err)
	}
	vault, err := crypto.Encrypt([]byte("KEY=value\n"), []byte("correct-horse-battery-staple-42!"), provider)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	dir := t.TempDir()
	vaultPath := filepath.Join(dir, "v.env.vault")
	if err := os.WriteFile(vaultPath, vault, 0600); err != nil {
		t.Fatalf("write vault: %v", err)
	}

	outPath := filepath.Join(dir, "migrated.env.vault")
	to = "chacha20poly1305"
	output = outPath

	if err := migrateCmd.RunE(migrateCmd, []string{vaultPath}); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	originalAfter, err := os.ReadFile(vaultPath)
	if err != nil {
		t.Fatalf("read original vault: %v", err)
	}
	if string(originalAfter) != string(vault) {
		t.Fatalf("expected original vault to be untouched when --output is set")
	}

	migratedData, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("expected migrated output file: %v", err)
	}
	alg, err := crypto.PeekAlgorithm(migratedData)
	if err != nil {
		t.Fatalf("PeekAlgorithm: %v", err)
	}
	if alg != "chacha20poly1305" {
		t.Fatalf("expected migrated file to use chacha20poly1305, got %q", alg)
	}
}
