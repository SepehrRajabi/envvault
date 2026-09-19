package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVerifyCommandValidVault(t *testing.T) {
	vaultPath := filepath.Join(t.TempDir(), "v.env.vault")
	if err := os.WriteFile(vaultPath, newTestVault(t), 0600); err != nil {
		t.Fatalf("write vault: %v", err)
	}

	if err := verifyCmd.RunE(verifyCmd, []string{vaultPath}); err != nil {
		t.Fatalf("expected valid vault to verify, got %v", err)
	}
}

func TestVerifyCommandCorruptVault(t *testing.T) {
	vaultPath := filepath.Join(t.TempDir(), "v.env.vault")
	if err := os.WriteFile(vaultPath, []byte("not a real vault"), 0600); err != nil {
		t.Fatalf("write file: %v", err)
	}

	if err := verifyCmd.RunE(verifyCmd, []string{vaultPath}); err == nil {
		t.Fatal("expected corrupt vault to fail verification")
	}
}

func TestVerifyCommandOutputIncludesAlgorithm(t *testing.T) {
	vaultPath := filepath.Join(t.TempDir(), "v.env.vault")
	if err := os.WriteFile(vaultPath, newTestVault(t), 0600); err != nil {
		t.Fatalf("write vault: %v", err)
	}

	out := captureStdout(t, func() {
		if err := verifyCmd.RunE(verifyCmd, []string{vaultPath}); err != nil {
			t.Fatalf("verify: %v", err)
		}
	})

	if !strings.Contains(out, "aes256gcm-argon2id") {
		t.Fatalf("expected output to mention algorithm, got:\n%s", out)
	}
}
