package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"

	"github.com/SepehrRajabi/envvault/crypto"
)

const testPass = "correct-horse-battery-staple-91"

func vaultAlg(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	alg, err := crypto.PeekAlgorithm(data)
	if err != nil {
		t.Fatal(err)
	}
	return alg
}

func writeVaultWith(t *testing.T, alg, content string) string {
	t.Helper()
	p, err := crypto.GetProvider(alg)
	if err != nil {
		t.Fatal(err)
	}
	enc, err := crypto.Encrypt([]byte(content), []byte(testPass), p)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "v.env.vault")
	if err := os.WriteFile(path, enc, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestModifyingCommandsPreserveAlgorithm(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("ENVVAULT_PASSWORD", testPass)
	algorithm = ""

	for _, alg := range []string{"chacha20poly1305", "aes256gcm-pbkdf2", "age-passphrase"} {
		t.Run(alg+"/set", func(t *testing.T) {
			path := writeVaultWith(t, alg, "A=1\n")
			if err := setCmd.RunE(setCmd, []string{path, "B", "2"}); err != nil {
				t.Fatal(err)
			}
			if got := vaultAlg(t, path); got != alg {
				t.Fatalf("set changed algorithm %s -> %s", alg, got)
			}
		})
		t.Run(alg+"/migrate-same", func(t *testing.T) {
			path := writeVaultWith(t, alg, "A=1\n")
			from, to, output = "", "", ""
			if err := migrateCmd.RunE(migrateCmd, []string{path}); err != nil {
				t.Fatal(err)
			}
			if got := vaultAlg(t, path); got != alg {
				t.Fatalf("migrate without --to changed algorithm %s -> %s", alg, got)
			}
		})
	}
}

func TestMigrateToInsecureRequiresFlag(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("ENVVAULT_PASSWORD", testPass)
	algorithm = ""
	path := writeVaultWith(t, "aes256gcm-argon2id", "A=1\n")

	from, to, output = "", "chacha20", ""
	t.Cleanup(func() { to, migrateAllowInsecure = "", false })
	err := migrateCmd.RunE(migrateCmd, []string{path})
	if err == nil || !strings.Contains(err.Error(), "not secure") {
		t.Fatalf("expected insecure-algorithm rejection, got %v", err)
	}
	if got := vaultAlg(t, path); got != "aes256gcm-argon2id" {
		t.Fatalf("vault was modified despite rejection: %s", got)
	}
	migrateAllowInsecure = true
	if err := migrateCmd.RunE(migrateCmd, []string{path}); err != nil {
		t.Fatalf("--allow-insecure should permit it: %v", err)
	}
}

func TestShamirVaultSurvivesSetWithSameShares(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	algorithm = ""
	p := crypto.NewShamirProvider(5, 3)
	enc, err := crypto.Encrypt([]byte("A=1\n"), []byte(testPass), p)
	if err != nil {
		t.Fatal(err)
	}
	shares := p.GeneratedShares()
	path := filepath.Join(t.TempDir(), "s.env.vault")
	os.WriteFile(path, enc, 0600)

	t.Setenv("ENVVAULT_PASSWORD", strings.Join(shares[:3], ","))
	if err := setCmd.RunE(setCmd, []string{path, "B", "2"}); err != nil {
		t.Fatalf("set on shamir vault: %v", err)
	}
	if got := vaultAlg(t, path); got != "shamir-aes256gcm" {
		t.Fatalf("algorithm became %s", got)
	}
	// A different quorum of the ORIGINAL shares must still open it.
	t.Setenv("ENVVAULT_PASSWORD", strings.Join(shares[2:5], ","))
	doc, err := loadEnvDocument(path)
	if err != nil {
		t.Fatalf("original shares no longer unlock the vault: %v", err)
	}
	defer doc.Close()
	if !strings.Contains(string(doc.Plaintext()), "B=2") {
		t.Fatalf("edit lost: %q", doc.Plaintext())
	}
}

func TestRotateKeepsAlgorithmAndRejectsPubkey(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("ENVVAULT_PASSWORD", testPass)
	algorithm = ""

	path := writeVaultWith(t, "chacha20poly1305", "A=1\n")
	// rotate prompts for a new password via GetPassword -> same env var
	if err := rotateCmd.RunE(rotateCmd, []string{path}); err != nil {
		t.Fatal(err)
	}
	if got := vaultAlg(t, path); got != "chacha20poly1305" {
		t.Fatalf("rotate changed algorithm to %s", got)
	}

	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	p, _ := crypto.GetProvider("age-pubkey")
	enc, err := crypto.Encrypt([]byte("A=1\n"), []byte(id.Recipient().String()), p)
	if err != nil {
		t.Fatal(err)
	}
	pub := filepath.Join(t.TempDir(), "p.env.vault")
	os.WriteFile(pub, enc, 0600)
	t.Setenv("AGE_IDENTITY", id.String())
	if err := rotateCmd.RunE(rotateCmd, []string{pub}); err == nil || !strings.Contains(err.Error(), "public-key") {
		t.Fatalf("expected pubkey rotate rejection, got %v", err)
	}
}
