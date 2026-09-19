package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// chdir switches the process working directory for the duration of the test
// and restores it afterward. status.go and guard.go operate on "." directly.
func chdir(t *testing.T, dir string) {
	t.Helper()
	orig, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("Chdir: %v", err)
	}
	t.Cleanup(func() {
		_ = os.Chdir(orig)
	})
}

func TestFindVaultFilesFiltersBySuffix(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"a.env.vault", "b.env.vault", "c.env", "notes.txt"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}

	files, err := findVaultFiles(dir)
	if err != nil {
		t.Fatalf("findVaultFiles: %v", err)
	}
	if len(files) != 2 {
		t.Fatalf("expected 2 vault files, got %v", files)
	}
}

func TestStatusCommandNoVaultsMessage(t *testing.T) {
	chdir(t, t.TempDir())

	out := captureStdout(t, func() {
		if err := statusCmd.RunE(statusCmd, nil); err != nil {
			t.Fatalf("status: %v", err)
		}
	})

	if !strings.Contains(out, "No vault files found") {
		t.Fatalf("expected 'no vault files' message, got:\n%s", out)
	}
}

func TestStatusCommandListsVaultAlgorithm(t *testing.T) {
	dir := t.TempDir()
	chdir(t, dir)

	if err := os.WriteFile("prod.env.vault", newTestVault(t), 0600); err != nil {
		t.Fatalf("write vault: %v", err)
	}

	out := captureStdout(t, func() {
		if err := statusCmd.RunE(statusCmd, nil); err != nil {
			t.Fatalf("status: %v", err)
		}
	})

	if !strings.Contains(out, "prod.env.vault") || !strings.Contains(out, "aes256gcm-argon2id") {
		t.Fatalf("expected output to list vault file and algorithm, got:\n%s", out)
	}
}

func TestHasGitignorePatternsRequiresBothMarkers(t *testing.T) {
	dir := t.TempDir()
	chdir(t, dir)

	if hasGitignorePatterns() {
		t.Fatal("expected no .gitignore to report false")
	}

	if err := os.WriteFile(".gitignore", []byte(".env\n!.env.vault\n"), 0600); err != nil {
		t.Fatalf("write .gitignore: %v", err)
	}
	if !hasGitignorePatterns() {
		t.Fatal("expected configured .gitignore to report true")
	}
}
