package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDockerCommandOutputsKeyValueLines(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("ENVVAULT_PASSWORD", "password123")
	algorithm = ""
	dockerOutput = ""
	t.Cleanup(func() { dockerOutput = "" })

	vaultPath := filepath.Join(t.TempDir(), "v.env.vault")
	if err := os.WriteFile(vaultPath, newTestVault(t), 0600); err != nil {
		t.Fatalf("write vault: %v", err)
	}

	out := captureStdout(t, func() {
		if err := dockerCmd.RunE(dockerCmd, []string{vaultPath}); err != nil {
			t.Fatalf("docker: %v", err)
		}
	})

	if strings.TrimSpace(out) != "secret=very_secret" {
		t.Fatalf("unexpected docker output: %q", out)
	}
}

func TestDockerCommandOutputFile(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("ENVVAULT_PASSWORD", "password123")
	algorithm = ""
	dir := t.TempDir()
	outPath := filepath.Join(dir, "docker.env")
	dockerOutput = outPath
	t.Cleanup(func() { dockerOutput = "" })

	vaultPath := filepath.Join(dir, "v.env.vault")
	if err := os.WriteFile(vaultPath, newTestVault(t), 0600); err != nil {
		t.Fatalf("write vault: %v", err)
	}

	if err := dockerCmd.RunE(dockerCmd, []string{vaultPath}); err != nil {
		t.Fatalf("docker -o: %v", err)
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("expected output file to be written: %v", err)
	}
	if strings.TrimSpace(string(data)) != "secret=very_secret" {
		t.Fatalf("unexpected file content: %q", data)
	}
}
