package cmd

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestRunCommandInjectsDecryptedEnvVars(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("relies on a POSIX shell")
	}
	t.Setenv("HOME", t.TempDir())
	algorithm = ""

	dir := t.TempDir()
	envPath := filepath.Join(dir, ".env")
	if err := os.WriteFile(envPath, []byte("INJECTED_VAR=hello-from-vault\n"), 0600); err != nil {
		t.Fatalf("write env file: %v", err)
	}
	outPath := filepath.Join(dir, "out.txt")

	// Plain (non-vault) env file: run.go's loadVars skips the password
	// prompt entirely for non-".env.vault" content, so this is safe to
	// exercise without any stdin/keyring setup.
	args := []string{envPath, "sh", "-c", "echo \"$INJECTED_VAR\" > \"$1\"", "run-test", outPath}
	if err := runCmd.RunE(runCmd, args); err != nil {
		t.Fatalf("run: %v", err)
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("expected child process to write output file: %v", err)
	}
	if strings.TrimSpace(string(data)) != "hello-from-vault" {
		t.Fatalf("expected injected env var to reach child process, got %q", data)
	}
}
