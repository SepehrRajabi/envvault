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

func TestRequireTrustFailsWithoutPin(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("ENVVAULT_REQUIRE_TRUST", "")
	vault := filepath.Join(t.TempDir(), "u.env.vault")
	data := writeVault(t, vault, "A=1\n", "correct-horse-battery-staple-91")

	// Default: warn and continue.
	if err := enforceTrust(vault, data); err != nil {
		t.Fatalf("unpinned vault should only warn by default: %v", err)
	}

	// Flag.
	requireTrust = true
	err := enforceTrust(vault, data)
	requireTrust = false
	if err == nil || !strings.Contains(err.Error(), "no trust pin") {
		t.Fatalf("--require-trust: expected hard failure, got %v", err)
	}

	// Env var.
	for _, v := range []string{"1", "true", "YES", "on"} {
		t.Setenv("ENVVAULT_REQUIRE_TRUST", v)
		if err := enforceTrust(vault, data); err == nil {
			t.Errorf("ENVVAULT_REQUIRE_TRUST=%s: expected failure", v)
		}
	}
	t.Setenv("ENVVAULT_REQUIRE_TRUST", "0")
	if err := enforceTrust(vault, data); err != nil {
		t.Errorf("ENVVAULT_REQUIRE_TRUST=0 should not require trust: %v", err)
	}

	// A pinned vault passes even in strict mode.
	t.Setenv("ENVVAULT_REQUIRE_TRUST", "1")
	if err := crypto.SetTrust(vault, crypto.TrustRecord{
		Algorithm: "aes256gcm-argon2id", Checksum: crypto.HashVaultChecksum(data),
	}); err != nil {
		t.Fatal(err)
	}
	if err := enforceTrust(vault, data); err != nil {
		t.Errorf("pinned vault rejected in strict mode: %v", err)
	}
}

func TestPinnedVaultReplacedByPlaintextIsRejected(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	path := filepath.Join(t.TempDir(), "secrets.enc") // no .vault suffix
	if err := crypto.SetTrust(path, crypto.TrustRecord{Algorithm: "aes256gcm-argon2id"}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("TOKEN=ATTACKER\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadEnvDocument(path); err == nil || !strings.Contains(err.Error(), "pinned as a vault") {
		t.Fatalf("loadEnvDocument: expected downgrade rejection, got %v", err)
	}
	if _, err := loadEnvVarsForSchema(path); err == nil {
		t.Fatal("schema loader accepted plaintext for a pinned vault")
	}
	if err := runCmd.RunE(runCmd, []string{path, "true"}); err == nil {
		t.Fatal("run accepted plaintext for a pinned vault")
	}
	// An unpinned plain .env is still fine.
	plain := filepath.Join(t.TempDir(), ".env")
	os.WriteFile(plain, []byte("A=1\n"), 0600)
	if _, err := loadEnvDocument(plain); err != nil {
		t.Fatalf("plain env rejected: %v", err)
	}
}

func TestValidateHistoryEndpoint(t *testing.T) {
	for ep, ok := range map[string]bool{
		"https://history.example.com": true,
		"http://localhost:8080":       true,
		"http://127.0.0.1:9000":       true,
		"http://[::1]:9000":           true,
		"http://history.example.com":  false,
		"ftp://x.example.com":         false,
		"not a url":                   false,
	} {
		if err := validateHistoryEndpoint(ep); (err == nil) != ok {
			t.Errorf("validateHistoryEndpoint(%q) err=%v, want ok=%v", ep, err, ok)
		}
	}
}

func TestSanitizeForTerminal(t *testing.T) {
	if got := sanitizeForTerminal("ok\x1b[31mred\r\x07\u009b"); strings.ContainsAny(got, "\x1b\r\x07\u009b") {
		t.Errorf("control chars survived: %q", got)
	}
	if got := sanitizeForTerminal("Ünïcode ✓"); got != "Ünïcode ✓" {
		t.Errorf("printable text altered: %q", got)
	}
}

func TestK8sRejectsUnsafeNames(t *testing.T) {
	for _, bad := range []string{"a: b", "x y", "a#b", "ok\nINJECT"} {
		if k8sSecretKeyPattern.MatchString(bad) {
			t.Errorf("key %q should be rejected", bad)
		}
	}
	if !k8sSecretKeyPattern.MatchString("DB_PASSWORD") || !k8sNamePattern.MatchString("my-app.secret") {
		t.Error("valid names rejected")
	}
}

func TestComposeEscapesDollarInSecrets(t *testing.T) {
	if got := yamlSecretScalar("pa$$${HOME}"); got != `"pa$$$$$${HOME}"` {
		t.Errorf("got %s", got)
	}
	if got := yamlScalar("${TAG}"); got != `"${TAG}"` {
		t.Errorf("non-secret scalars must not be escaped: %s", got)
	}
}

func TestVerifyCommitHashPattern(t *testing.T) {
	for h, ok := range map[string]bool{
		"55c4064a97c264eee03a9dc62260db124ccc3355": true,
		"--help": false,
		"-h":     false,
		"55c4064a97c264eee03a9dc62260db124ccc3355; rm -rf": false,
		"": false,
	} {
		if gitHashPattern.MatchString(h) != ok {
			t.Errorf("gitHashPattern(%q) = %v, want %v", h, !ok, ok)
		}
	}
}
