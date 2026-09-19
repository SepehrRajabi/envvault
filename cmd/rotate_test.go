package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/SepehrRajabi/envvault/crypto"
)

func TestRotateCommandRoundTrip(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("ENVVAULT_PASSWORD", "correct-horse-battery-staple-42!")
	algorithm = ""
	rotateAllowWeak = false
	t.Cleanup(func() { rotateAllowWeak = false })

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

	if err := rotateCmd.RunE(rotateCmd, []string{vaultPath}); err != nil {
		t.Fatalf("rotate: %v", err)
	}

	after, err := os.ReadFile(vaultPath)
	if err != nil {
		t.Fatalf("read vault after rotate: %v", err)
	}
	plaintext, err := crypto.Decrypt(after, []byte("correct-horse-battery-staple-42!"), nil)
	if err != nil {
		t.Fatalf("decrypt rotated vault: %v", err)
	}
	if string(plaintext) != "KEY=value\n" {
		t.Fatalf("unexpected plaintext after rotate: %q", plaintext)
	}
}

func TestRotateCommandRejectsWeakNewPassword(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("ENVVAULT_PASSWORD", "abc123")
	algorithm = ""
	rotateAllowWeak = false
	t.Cleanup(func() { rotateAllowWeak = false })

	// Old and new password prompts both resolve to ENVVAULT_PASSWORD, which
	// is weak; rotate must refuse to re-encrypt with it unless --allow-weak.
	vault, err := crypto.Encrypt([]byte("KEY=value\n"), []byte("abc123"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	dir := t.TempDir()
	vaultPath := filepath.Join(dir, "v.env.vault")
	if err := os.WriteFile(vaultPath, vault, 0600); err != nil {
		t.Fatalf("write vault: %v", err)
	}

	if err := rotateCmd.RunE(rotateCmd, []string{vaultPath}); err == nil {
		t.Fatal("expected weak new password to be rejected")
	}

	rotateAllowWeak = true
	if err := rotateCmd.RunE(rotateCmd, []string{vaultPath}); err != nil {
		t.Fatalf("expected --allow-weak to bypass strength check, got %v", err)
	}
}

func TestRotateCommandWrongPasswordFails(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("ENVVAULT_PASSWORD", "totally-wrong-password-here!")
	algorithm = ""

	provider, err := crypto.GetProvider("aes256gcm-argon2id")
	if err != nil {
		t.Fatalf("GetProvider: %v", err)
	}
	vault, err := crypto.Encrypt([]byte("KEY=value\n"), []byte("actual-password-here!"), provider)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	dir := t.TempDir()
	vaultPath := filepath.Join(dir, "v.env.vault")
	if err := os.WriteFile(vaultPath, vault, 0600); err != nil {
		t.Fatalf("write vault: %v", err)
	}

	if err := rotateCmd.RunE(rotateCmd, []string{vaultPath}); err == nil {
		t.Fatal("expected rotate with wrong password to fail")
	}
}
