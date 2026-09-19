package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExportCommandPrintsEnvLines(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("ENVVAULT_PASSWORD", "password123")
	algorithm = ""

	vaultPath := filepath.Join(t.TempDir(), "v.env.vault")
	if err := os.WriteFile(vaultPath, newTestVault(t), 0600); err != nil {
		t.Fatalf("write vault: %v", err)
	}

	out := captureStdout(t, func() {
		if err := exportCmd.RunE(exportCmd, []string{vaultPath}); err != nil {
			t.Fatalf("export: %v", err)
		}
	})

	if !strings.Contains(out, "secret=very_secret") {
		t.Fatalf("expected export output to contain the decrypted variable, got %q", out)
	}
}

func TestExportCommandInvalidVaultErrors(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	algorithm = ""

	vaultPath := filepath.Join(t.TempDir(), "corrupt.env.vault")
	if err := os.WriteFile(vaultPath, []byte("not a vault"), 0600); err != nil {
		t.Fatalf("write file: %v", err)
	}

	if err := exportCmd.RunE(exportCmd, []string{vaultPath}); err == nil {
		t.Fatal("expected export of a corrupt vault to fail")
	}
}
