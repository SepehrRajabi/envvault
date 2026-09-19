package cmd

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func resetK8sFlags() {
	k8sName = "my-app-secret"
	k8sNamespace = "default"
	k8sType = "Opaque"
	k8sOutput = ""
	algorithm = ""
}

func TestK8sCommandDefaultOutput(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("ENVVAULT_PASSWORD", "password123")
	resetK8sFlags()
	t.Cleanup(resetK8sFlags)

	vaultPath := filepath.Join(t.TempDir(), "v.env.vault")
	if err := os.WriteFile(vaultPath, newTestVault(t), 0600); err != nil {
		t.Fatalf("write vault: %v", err)
	}

	out := captureStdout(t, func() {
		if err := k8sCmd.RunE(k8sCmd, []string{vaultPath}); err != nil {
			t.Fatalf("k8s: %v", err)
		}
	})

	if !strings.Contains(out, "name: my-app-secret") {
		t.Fatalf("expected default secret name in output, got:\n%s", out)
	}
	if !strings.Contains(out, "namespace: default") {
		t.Fatalf("expected default namespace in output, got:\n%s", out)
	}
	wantValue := base64.StdEncoding.EncodeToString([]byte("very_secret"))
	if !strings.Contains(out, "secret: "+wantValue) {
		t.Fatalf("expected base64-encoded secret value in output, got:\n%s", out)
	}
}

func TestK8sCommandCustomNameAndNamespace(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("ENVVAULT_PASSWORD", "password123")
	resetK8sFlags()
	t.Cleanup(resetK8sFlags)
	k8sName = "prod-secret"
	k8sNamespace = "production"

	vaultPath := filepath.Join(t.TempDir(), "v.env.vault")
	if err := os.WriteFile(vaultPath, newTestVault(t), 0600); err != nil {
		t.Fatalf("write vault: %v", err)
	}

	out := captureStdout(t, func() {
		if err := k8sCmd.RunE(k8sCmd, []string{vaultPath}); err != nil {
			t.Fatalf("k8s: %v", err)
		}
	})

	if !strings.Contains(out, "name: prod-secret") || !strings.Contains(out, "namespace: production") {
		t.Fatalf("expected custom name/namespace in output, got:\n%s", out)
	}
}

func TestK8sCommandOutputFile(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("ENVVAULT_PASSWORD", "password123")
	resetK8sFlags()
	t.Cleanup(resetK8sFlags)

	dir := t.TempDir()
	outPath := filepath.Join(dir, "secret.yaml")
	k8sOutput = outPath

	vaultPath := filepath.Join(dir, "v.env.vault")
	if err := os.WriteFile(vaultPath, newTestVault(t), 0600); err != nil {
		t.Fatalf("write vault: %v", err)
	}

	if err := k8sCmd.RunE(k8sCmd, []string{vaultPath}); err != nil {
		t.Fatalf("k8s -o: %v", err)
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("expected output file to be written: %v", err)
	}
	if !strings.Contains(string(data), "kind: Secret") {
		t.Fatalf("unexpected file content: %s", data)
	}
}
