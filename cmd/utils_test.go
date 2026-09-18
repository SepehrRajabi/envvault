package cmd

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/SepehrRajabi/envvault/crypto"
)

// newTestVault builds a valid password-encrypted vault using the default
// AES-GCM provider so tests can exercise trust enforcement without prompts.
func newTestVault(t *testing.T) []byte {
	t.Helper()
	provider, err := crypto.GetProvider("aes256gcm-argon2id")
	if err != nil {
		t.Fatalf("GetProvider: %v", err)
	}
	vault, err := crypto.Encrypt([]byte("secret=very_secret\n"), []byte("password123"), provider)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	return vault
}

func TestEnforceTrustBlocksAlgorithmSubstitution(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	vault := newTestVault(t)
	vaultPath := filepath.Join(t.TempDir(), "v.env.vault")
	if err := os.WriteFile(vaultPath, vault, 0600); err != nil {
		t.Fatalf("write vault: %v", err)
	}

	// Pin as age-pubkey while the file is actually aes256gcm-argon2id:
	// simulates an attacker swapping a password vault for a forged one.
	if err := crypto.SetTrust(vaultPath, crypto.TrustRecord{Algorithm: "age-pubkey"}); err != nil {
		t.Fatalf("SetTrust: %v", err)
	}

	if err := enforceTrust(vaultPath, vault); err == nil {
		t.Fatal("expected enforceTrust to block algorithm substitution")
	}
}

func TestEnforceTrustAllowsMatchingPin(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	vault := newTestVault(t)
	vaultPath := filepath.Join(t.TempDir(), "v.env.vault")
	if err := os.WriteFile(vaultPath, vault, 0600); err != nil {
		t.Fatalf("write vault: %v", err)
	}

	if err := crypto.SetTrust(vaultPath, crypto.TrustRecord{Algorithm: "aes256gcm-argon2id"}); err != nil {
		t.Fatalf("SetTrust: %v", err)
	}

	if err := enforceTrust(vaultPath, vault); err != nil {
		t.Fatalf("expected matching pin to pass, got %v", err)
	}
}

func TestEnforceTrustUntrustedIsWarningNotError(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	vault := newTestVault(t)
	vaultPath := filepath.Join(t.TempDir(), "v.env.vault")
	if err := os.WriteFile(vaultPath, vault, 0600); err != nil {
		t.Fatalf("write vault: %v", err)
	}

	// No pin recorded: first-time use must be allowed (with a warning), not blocked.
	if err := enforceTrust(vaultPath, vault); err != nil {
		t.Fatalf("expected untrusted vault to pass with warning, got %v", err)
	}
}

func TestQuorumStateSaveLoad(t *testing.T) {
	dir := t.TempDir()
	vaultPath := filepath.Join(dir, "example.env.vault")
	if err := os.WriteFile(vaultPath, []byte("data"), 0600); err != nil {
		t.Fatalf("write vault file: %v", err)
	}

	statePath, err := quorumStatePath(vaultPath)
	if err != nil {
		t.Fatalf("quorumStatePath: %v", err)
	}

	state := &quorumState{
		VaultPath:   vaultPath,
		PayloadHash: "deadbeef",
		Threshold:   2,
		Shares:      []string{"share1", "share2"},
	}

	if err := saveQuorumState(statePath, state); err != nil {
		t.Fatalf("saveQuorumState: %v", err)
	}

	loaded, err := loadQuorumState(statePath)
	if err != nil {
		t.Fatalf("loadQuorumState: %v", err)
	}

	if !reflect.DeepEqual(state, loaded) {
		t.Fatalf("expected loaded state %+v, got %+v", state, loaded)
	}
}
