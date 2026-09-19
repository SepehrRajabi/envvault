package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func resetInspectFlags() {
	jsonMetadata = false
}

func TestInspectCommandTextOutput(t *testing.T) {
	resetInspectFlags()
	t.Cleanup(resetInspectFlags)

	vaultPath := filepath.Join(t.TempDir(), "v.env.vault")
	if err := os.WriteFile(vaultPath, newTestVault(t), 0600); err != nil {
		t.Fatalf("write vault: %v", err)
	}

	out := captureStdout(t, func() {
		if err := inspectCmd.RunE(inspectCmd, []string{vaultPath}); err != nil {
			t.Fatalf("inspect: %v", err)
		}
	})

	if !strings.Contains(out, "aes256gcm-argon2id") {
		t.Fatalf("expected output to include algorithm, got:\n%s", out)
	}
	if !strings.Contains(out, "password") {
		t.Fatalf("expected output to include auth method, got:\n%s", out)
	}
}

func TestInspectCommandJSONOutput(t *testing.T) {
	resetInspectFlags()
	t.Cleanup(resetInspectFlags)
	jsonMetadata = true

	vaultPath := filepath.Join(t.TempDir(), "v.env.vault")
	if err := os.WriteFile(vaultPath, newTestVault(t), 0600); err != nil {
		t.Fatalf("write vault: %v", err)
	}

	out := captureStdout(t, func() {
		if err := inspectCmd.RunE(inspectCmd, []string{vaultPath}); err != nil {
			t.Fatalf("inspect --json: %v", err)
		}
	})

	var parsed jsonMetadataOutput
	if err := json.Unmarshal([]byte(out), &parsed); err != nil {
		t.Fatalf("expected valid JSON output, got error %v for:\n%s", err, out)
	}
	if parsed.Algorithm.ID != "aes256gcm-argon2id" {
		t.Fatalf("unexpected algorithm ID %q", parsed.Algorithm.ID)
	}
	if parsed.File != vaultPath {
		t.Fatalf("unexpected file field %q", parsed.File)
	}
}

func TestInspectCommandInvalidVaultErrors(t *testing.T) {
	resetInspectFlags()
	t.Cleanup(resetInspectFlags)

	vaultPath := filepath.Join(t.TempDir(), "corrupt.env.vault")
	if err := os.WriteFile(vaultPath, []byte("not a vault"), 0600); err != nil {
		t.Fatalf("write file: %v", err)
	}

	if err := inspectCmd.RunE(inspectCmd, []string{vaultPath}); err == nil {
		t.Fatal("expected inspect of corrupt vault to fail")
	}
}
