package cmd

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestIsDangerousEnvFile(t *testing.T) {
	cases := map[string]bool{
		".env":            true,
		".env.local":      true,
		".env.production": true,
		".env.vault":      false,
		".env.example":    false,
		".env.template":   false,
		".env.sample":     false,
		"config/.env":     true,
		"notes.txt":       false,
		"envfile.go":      false,
	}
	for file, want := range cases {
		if got := isDangerousEnvFile(file); got != want {
			t.Errorf("isDangerousEnvFile(%q) = %v, want %v", file, got, want)
		}
	}
}

func TestInitGitignoreCreatesFileWithPatterns(t *testing.T) {
	chdir(t, t.TempDir())

	if err := initGitignore(); err != nil {
		t.Fatalf("initGitignore: %v", err)
	}

	data, err := os.ReadFile(".gitignore")
	if err != nil {
		t.Fatalf("expected .gitignore to be created: %v", err)
	}
	for _, want := range []string{".env", "!.env.vault"} {
		if !strings.Contains(string(data), want) {
			t.Fatalf("expected .gitignore to contain %q, got:\n%s", want, data)
		}
	}
}

func TestInitGitignoreIsIdempotent(t *testing.T) {
	chdir(t, t.TempDir())

	if err := initGitignore(); err != nil {
		t.Fatalf("initGitignore (first run): %v", err)
	}
	first, err := os.ReadFile(".gitignore")
	if err != nil {
		t.Fatalf("read .gitignore: %v", err)
	}

	if err := initGitignore(); err != nil {
		t.Fatalf("initGitignore (second run): %v", err)
	}
	second, err := os.ReadFile(".gitignore")
	if err != nil {
		t.Fatalf("read .gitignore: %v", err)
	}

	if string(first) != string(second) {
		t.Fatalf("expected re-running init to leave .gitignore unchanged:\nfirst:\n%s\nsecond:\n%s", first, second)
	}
}

func TestInstallPreCommitHookRequiresGitDir(t *testing.T) {
	chdir(t, t.TempDir())

	if err := installPreCommitHook(); err == nil {
		t.Fatal("expected installPreCommitHook to fail without .git/hooks")
	}
}

func TestInstallPreCommitHookCreatesHook(t *testing.T) {
	dir := t.TempDir()
	chdir(t, dir)

	if err := os.MkdirAll(filepath.Join(dir, ".git", "hooks"), 0700); err != nil {
		t.Fatalf("mkdir .git/hooks: %v", err)
	}

	if err := installPreCommitHook(); err != nil {
		t.Fatalf("installPreCommitHook: %v", err)
	}

	if !hasPreCommitHook() {
		t.Fatal("expected hasPreCommitHook to report true after install")
	}
}

func TestCheckStagedFilesDetectsUnencryptedEnv(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}

	dir := t.TempDir()
	chdir(t, dir)

	run := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}

	run("init", "-q")
	run("config", "user.email", "test@example.com")
	run("config", "user.name", "Test")

	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("SECRET=1\n"), 0600); err != nil {
		t.Fatalf("write .env: %v", err)
	}
	run("add", ".env")

	if err := checkStagedFiles(); err == nil {
		t.Fatal("expected checkStagedFiles to flag a staged .env file")
	}
}
