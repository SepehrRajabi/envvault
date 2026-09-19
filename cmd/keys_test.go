package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestKeysAddCommandPrintsConfirmation(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	vaultPath := filepath.Join(t.TempDir(), "v.env.vault")
	if err := os.WriteFile(vaultPath, newTestVault(t), 0600); err != nil {
		t.Fatalf("write vault: %v", err)
	}

	out := captureStdout(t, func() {
		if err := keysAddCmd.RunE(keysAddCmd, []string{vaultPath, "alice", "age1abc"}); err != nil {
			t.Fatalf("keys add: %v", err)
		}
	})

	if !strings.Contains(out, "alice") || !strings.Contains(out, "age1abc") {
		t.Fatalf("expected confirmation to mention name and key, got:\n%s", out)
	}
}

func TestKeysAddCommandInvalidVaultErrors(t *testing.T) {
	vaultPath := filepath.Join(t.TempDir(), "corrupt.env.vault")
	if err := os.WriteFile(vaultPath, []byte("not a vault"), 0600); err != nil {
		t.Fatalf("write file: %v", err)
	}

	if err := keysAddCmd.RunE(keysAddCmd, []string{vaultPath, "alice", "age1abc"}); err == nil {
		t.Fatal("expected keys add on a corrupt vault to fail")
	}
}

func TestKeysRemoveCommandRequiresRecipients(t *testing.T) {
	// newTestVault is a password vault with no recipients metadata at all.
	vaultPath := filepath.Join(t.TempDir(), "v.env.vault")
	if err := os.WriteFile(vaultPath, newTestVault(t), 0600); err != nil {
		t.Fatalf("write vault: %v", err)
	}

	if err := keysRemoveCmd.RunE(keysRemoveCmd, []string{vaultPath, "alice"}); err == nil {
		t.Fatal("expected keys remove to fail when vault has no recipients")
	}
}
