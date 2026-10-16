package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/SepehrRajabi/envvault/crypto"
)

// writeVault encrypts content under password and writes it to path.
func writeVault(t *testing.T, path, content, password string) []byte {
	t.Helper()
	enc, err := crypto.Encrypt([]byte(content), []byte(password))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if err := os.WriteFile(path, enc, 0600); err != nil {
		t.Fatal(err)
	}
	return enc
}

// A pinned vault that is swapped on disk must be rejected by every path that
// reads it, not just unlock/export/run.
func TestSubstitutedVaultRejectedByAllReaders(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("ENVVAULT_PASSWORD", "correct-horse-battery-staple-91")
	dir := t.TempDir()
	vault := filepath.Join(dir, "a.env.vault")

	good := writeVault(t, vault, "TOKEN=legit\n", "correct-horse-battery-staple-91")
	if err := crypto.SetTrust(vault, crypto.TrustRecord{
		Algorithm: "aes256gcm-argon2id",
		Checksum:  crypto.HashVaultChecksum(good),
	}); err != nil {
		t.Fatal(err)
	}
	writeVault(t, vault, "TOKEN=ATTACKER\n", "correct-horse-battery-staple-91")

	readers := map[string]func() error{
		"loadEnvDocument": func() error { _, err := loadEnvDocument(vault); return err },
		"schema":          func() error { _, err := loadEnvVarsForSchema(vault); return err },
		"docker":          func() error { return dockerCmd.RunE(dockerCmd, []string{vault}) },
		"k8s":             func() error { return k8sCmd.RunE(k8sCmd, []string{vault}) },
		"unlock-quorum": func() error {
			requestAccess = true
			defer func() { requestAccess = false }()
			return unlockCmd.RunE(unlockCmd, []string{vault})
		},
	}
	for name, read := range readers {
		err := read()
		if err == nil || !strings.Contains(err.Error(), "pinned content") {
			t.Errorf("%s: expected substitution error, got %v", name, err)
		}
	}
}

// A legitimate set must refresh the pin so the next read doesn't false-positive.
func TestSetRefreshesTrustPin(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("ENVVAULT_PASSWORD", "correct-horse-battery-staple-91")
	vault := filepath.Join(t.TempDir(), "a.env.vault")

	good := writeVault(t, vault, "A=1\n", "correct-horse-battery-staple-91")
	if err := crypto.SetTrust(vault, crypto.TrustRecord{
		Algorithm: "aes256gcm-argon2id",
		Checksum:  crypto.HashVaultChecksum(good),
	}); err != nil {
		t.Fatal(err)
	}

	if err := setCmd.RunE(setCmd, []string{vault, "B", "2"}); err != nil {
		t.Fatalf("set: %v", err)
	}
	doc, err := loadEnvDocument(vault)
	if err != nil {
		t.Fatalf("read after set should pass trust check: %v", err)
	}
	doc.Close()
}
