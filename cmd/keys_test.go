package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"

	"github.com/SepehrRajabi/envvault/crypto"
)

func TestKeysAddCommandPersistsNewRecipient(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	vault, _ := newTestAgePubkeyVault(t)
	vaultPath := filepath.Join(t.TempDir(), "v.env.vault")
	if err := os.WriteFile(vaultPath, vault, 0600); err != nil {
		t.Fatalf("write vault: %v", err)
	}

	newIdentity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("GenerateX25519Identity: %v", err)
	}
	newRecipient := newIdentity.Recipient().String()

	out := captureStdout(t, func() {
		if err := keysAddCmd.RunE(keysAddCmd, []string{vaultPath, "alice", newRecipient}); err != nil {
			t.Fatalf("keys add: %v", err)
		}
	})

	if !strings.Contains(out, "alice") || !strings.Contains(out, newRecipient) {
		t.Fatalf("expected confirmation to mention name and key, got:\n%s", out)
	}

	updated, err := os.ReadFile(vaultPath)
	if err != nil {
		t.Fatalf("read updated vault: %v", err)
	}
	hdr, err := crypto.Verify(updated)
	if err != nil {
		t.Fatalf("verify updated vault: %v", err)
	}
	recipients := crypto.RecipientsFromHeader(hdr)
	found := false
	for _, r := range recipients {
		if r == newRecipient {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected updated vault to include new recipient %s, got %v", newRecipient, recipients)
	}
}

func TestKeysAddCommandInvalidVaultErrors(t *testing.T) {
	vaultPath := filepath.Join(t.TempDir(), "corrupt.env.vault")
	if err := os.WriteFile(vaultPath, []byte("not a vault"), 0600); err != nil {
		t.Fatalf("write file: %v", err)
	}

	if err := keysAddCmd.RunE(keysAddCmd, []string{vaultPath, "alice", "age1abc"}); err == nil {
		t.Fatal("expected keys add on a corrupt vault to fail")
	}
}

func TestKeysAddCommandRejectsNonPubkeyVault(t *testing.T) {
	// newTestVault is a password vault, which has no recipient concept.
	vaultPath := filepath.Join(t.TempDir(), "v.env.vault")
	if err := os.WriteFile(vaultPath, newTestVault(t), 0600); err != nil {
		t.Fatalf("write vault: %v", err)
	}

	if err := keysAddCmd.RunE(keysAddCmd, []string{vaultPath, "alice", "age1abc"}); err == nil {
		t.Fatal("expected keys add on a password vault to fail")
	}
}

func TestKeysRemoveCommandPersistsRemoval(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("GenerateX25519Identity: %v", err)
	}
	keepIdentity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("GenerateX25519Identity: %v", err)
	}
	t.Setenv("AGE_IDENTITY", keepIdentity.String())

	pubKey := identity.Recipient().String()
	keepPubKey := keepIdentity.Recipient().String()

	provider := &crypto.AgePubKeyProvider{ID: "age-pubkey"}
	vault, err := crypto.Encrypt([]byte("secret=very_secret\n"), []byte(pubKey+","+keepPubKey), provider)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	vaultPath := filepath.Join(t.TempDir(), "v.env.vault")
	if err := os.WriteFile(vaultPath, vault, 0600); err != nil {
		t.Fatalf("write vault: %v", err)
	}

	out := captureStdout(t, func() {
		if err := keysRemoveCmd.RunE(keysRemoveCmd, []string{vaultPath, pubKey}); err != nil {
			t.Fatalf("keys remove: %v", err)
		}
	})
	if !strings.Contains(out, pubKey) {
		t.Fatalf("expected confirmation to mention removed key, got:\n%s", out)
	}

	updated, err := os.ReadFile(vaultPath)
	if err != nil {
		t.Fatalf("read updated vault: %v", err)
	}
	hdr, err := crypto.Verify(updated)
	if err != nil {
		t.Fatalf("verify updated vault: %v", err)
	}
	recipients := crypto.RecipientsFromHeader(hdr)
	for _, r := range recipients {
		if r == pubKey {
			t.Fatalf("expected %s to be removed, got recipients %v", pubKey, recipients)
		}
	}
}

func TestKeysRemoveCommandRequiresRecipients(t *testing.T) {
	// newTestVault is a password vault with no recipients metadata at all.
	vaultPath := filepath.Join(t.TempDir(), "v.env.vault")
	if err := os.WriteFile(vaultPath, newTestVault(t), 0600); err != nil {
		t.Fatalf("write vault: %v", err)
	}

	if err := keysRemoveCmd.RunE(keysRemoveCmd, []string{vaultPath, "age1abc"}); err == nil {
		t.Fatal("expected keys remove to fail when vault has no recipients")
	}
}

func TestKeysRemoveCommandRefusesToRemoveLastRecipient(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	vault, pubKey := newTestAgePubkeyVault(t)
	vaultPath := filepath.Join(t.TempDir(), "v.env.vault")
	if err := os.WriteFile(vaultPath, vault, 0600); err != nil {
		t.Fatalf("write vault: %v", err)
	}

	if err := keysRemoveCmd.RunE(keysRemoveCmd, []string{vaultPath, pubKey}); err == nil {
		t.Fatal("expected keys remove to refuse removing the last recipient")
	}
}
