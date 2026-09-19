package cmd

import (
	"os"
	"path/filepath"
	"testing"
)

func TestVerifyCommitCommandMissingMetadata(t *testing.T) {
	// crypto.Encrypt embeds git commit metadata automatically when run
	// inside a git repository, so this vault must be created with the
	// working directory outside of one to end up with no embedded commit.
	dir := t.TempDir()
	chdir(t, dir)

	vaultPath := filepath.Join(dir, "v.env.vault")
	if err := os.WriteFile(vaultPath, newTestVault(t), 0600); err != nil {
		t.Fatalf("write vault: %v", err)
	}

	if err := verifyCommitCmd.RunE(verifyCommitCmd, []string{vaultPath}); err == nil {
		t.Fatal("expected vault without commit metadata to fail verify-commit")
	}
}

func TestVerifyCommitCommandInvalidVault(t *testing.T) {
	vaultPath := filepath.Join(t.TempDir(), "corrupt.env.vault")
	if err := os.WriteFile(vaultPath, []byte("not a vault"), 0600); err != nil {
		t.Fatalf("write file: %v", err)
	}

	if err := verifyCommitCmd.RunE(verifyCommitCmd, []string{vaultPath}); err == nil {
		t.Fatal("expected corrupt vault to fail verify-commit")
	}
}

func TestGitSignatureStatusDescription(t *testing.T) {
	cases := map[string]string{
		"G": "GOOD",
		"U": "GOOD, UNTRUSTED",
		"B": "BAD",
		"N": "NO SIGNATURE",
		"?": "?",
	}
	for status, want := range cases {
		if got := gitSignatureStatusDescription(status); got != want {
			t.Errorf("gitSignatureStatusDescription(%q) = %q, want %q", status, got, want)
		}
	}
}
