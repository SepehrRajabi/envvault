package cmd

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/SepehrRajabi/envvault/crypto"
)

func writeExecutableScript(t *testing.T, dir, name, body string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("editor script test relies on a POSIX shell script")
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body+"\n"), 0700); err != nil {
		t.Fatalf("write script: %v", err)
	}
	return path
}

func TestEditCommandNoChangesLeavesVaultIntact(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("ENVVAULT_PASSWORD", "password123")
	algorithm = ""
	editRecipient = ""
	scriptDir := t.TempDir()
	editor := writeExecutableScript(t, scriptDir, "noop-editor.sh", "exit 0")
	t.Setenv("EDITOR", editor)

	dir := t.TempDir()
	vaultPath := filepath.Join(dir, "v.env.vault")
	original := newTestVault(t)
	if err := os.WriteFile(vaultPath, original, 0600); err != nil {
		t.Fatalf("write vault: %v", err)
	}

	if err := editCmd.RunE(editCmd, []string{vaultPath}); err != nil {
		t.Fatalf("edit: %v", err)
	}

	after, err := os.ReadFile(vaultPath)
	if err != nil {
		t.Fatalf("read vault after edit: %v", err)
	}
	if string(after) != string(original) {
		t.Fatalf("expected vault to be unchanged when editor makes no edits")
	}
}

func TestEditCommandSavesChanges(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("ENVVAULT_PASSWORD", "password123")
	algorithm = ""
	editRecipient = ""
	scriptDir := t.TempDir()
	editor := writeExecutableScript(t, scriptDir, "append-editor.sh", `echo "NEW_KEY=new_value" >> "$1"`)
	t.Setenv("EDITOR", editor)

	dir := t.TempDir()
	vaultPath := filepath.Join(dir, "v.env.vault")
	if err := os.WriteFile(vaultPath, newTestVault(t), 0600); err != nil {
		t.Fatalf("write vault: %v", err)
	}

	if err := editCmd.RunE(editCmd, []string{vaultPath}); err != nil {
		t.Fatalf("edit: %v", err)
	}

	after, err := os.ReadFile(vaultPath)
	if err != nil {
		t.Fatalf("read vault after edit: %v", err)
	}
	plaintext, err := crypto.Decrypt(after, []byte("password123"), nil)
	if err != nil {
		t.Fatalf("decrypt edited vault: %v", err)
	}
	if !strings.Contains(string(plaintext), "NEW_KEY=new_value") {
		t.Fatalf("expected edited content to contain new key, got %q", plaintext)
	}
}
