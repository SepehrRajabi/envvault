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

func TestEditCommandRefreshesTrustPin(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("ENVVAULT_PASSWORD", "password123")
	algorithm = ""
	editRecipient = ""
	scriptDir := t.TempDir()
	editor := writeExecutableScript(t, scriptDir, "append-editor.sh", `echo "NEW_KEY=new_value" >> "$1"`)
	t.Setenv("EDITOR", editor)

	dir := t.TempDir()
	vaultPath := filepath.Join(dir, "v.env.vault")
	vault := newTestVault(t)
	if err := os.WriteFile(vaultPath, vault, 0600); err != nil {
		t.Fatalf("write vault: %v", err)
	}
	if err := crypto.SetTrust(vaultPath, crypto.TrustRecord{
		Algorithm: "aes256gcm-argon2id",
		Checksum:  crypto.HashVaultChecksum(vault),
	}); err != nil {
		t.Fatalf("SetTrust: %v", err)
	}

	if err := editCmd.RunE(editCmd, []string{vaultPath}); err != nil {
		t.Fatalf("edit: %v", err)
	}

	// Editing necessarily changes the ciphertext. A stale content pin
	// would make the very next enforceTrust call falsely report
	// substitution.
	after, err := os.ReadFile(vaultPath)
	if err != nil {
		t.Fatalf("read vault after edit: %v", err)
	}
	if err := enforceTrust(vaultPath, after); err != nil {
		t.Fatalf("expected trust pin to be refreshed after edit, got %v", err)
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

// The plaintext temp file must live outside the vault's directory, in a
// private directory, and be removed (including editor leftovers) afterwards.
func TestEditCommandTempFileIsPrivateAndCleanedUp(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("ENVVAULT_PASSWORD", "password123")
	algorithm = ""
	editRecipient = ""
	scriptDir := t.TempDir()
	record := filepath.Join(scriptDir, "path.txt")
	editor := writeExecutableScript(t, scriptDir, "editor.sh",
		`echo "$1" > "`+record+`"; stat -f %Lp "$(dirname "$1")" >> "`+record+`" 2>/dev/null || stat -c %a "$(dirname "$1")" >> "`+record+`"
echo "X=1" >> "$1"; echo leftover > "$(dirname "$1")/.swp"`)
	t.Setenv("EDITOR", editor)

	dir := t.TempDir()
	vaultPath := filepath.Join(dir, "v.env.vault")
	if err := os.WriteFile(vaultPath, newTestVault(t), 0600); err != nil {
		t.Fatal(err)
	}

	if err := editCmd.RunE(editCmd, []string{vaultPath}); err != nil {
		t.Fatalf("edit: %v", err)
	}

	out, err := os.ReadFile(record)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Fields(string(out))
	tmpPath, mode := lines[0], lines[1]
	if filepath.Dir(filepath.Dir(tmpPath)) == dir || filepath.Dir(tmpPath) == dir {
		t.Errorf("temp file %s is inside the vault directory", tmpPath)
	}
	if mode != "700" {
		t.Errorf("temp dir mode = %s, want 700", mode)
	}
	if _, err := os.Stat(filepath.Dir(tmpPath)); !os.IsNotExist(err) {
		t.Errorf("temp dir %s was not removed", filepath.Dir(tmpPath))
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Errorf("vault directory has stray files: %v", entries)
	}
}

func TestEditorNoLeakArgs(t *testing.T) {
	if len(editorNoLeakArgs("/usr/bin/vim")) == 0 || len(editorNoLeakArgs("nvim")) == 0 {
		t.Error("expected leak-prevention flags for vim/nvim")
	}
	if editorNoLeakArgs("nano") != nil {
		t.Error("unexpected flags for nano")
	}
}
