package crypto

import (
	"testing"
)

func withTempHome(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("USERPROFILE", dir) // windows
}

func TestCheckTrustNoRecordIsUntrusted(t *testing.T) {
	withTempHome(t)

	hdr := &envelopeHeader{Algorithm: "aesgcm-argon2id"}
	if err := CheckTrust("/tmp/some.env.vault", []byte("vault-bytes"), hdr); err != ErrUntrustedVault {
		t.Fatalf("expected ErrUntrustedVault, got %v", err)
	}
}

func TestCheckTrustMatchingAlgorithmPasses(t *testing.T) {
	withTempHome(t)

	path := "/tmp/match.env.vault"
	if err := SetTrust(path, TrustRecord{Algorithm: "aesgcm-argon2id"}); err != nil {
		t.Fatalf("SetTrust: %v", err)
	}

	hdr := &envelopeHeader{Algorithm: "aesgcm-argon2id"}
	if err := CheckTrust(path, []byte("vault-bytes"), hdr); err != nil {
		t.Fatalf("expected trust check to pass, got %v", err)
	}
}

func TestCheckTrustAlgorithmMismatchFails(t *testing.T) {
	withTempHome(t)

	path := "/tmp/substituted.env.vault"
	if err := SetTrust(path, TrustRecord{Algorithm: "aesgcm-argon2id"}); err != nil {
		t.Fatalf("SetTrust: %v", err)
	}

	// Simulates an attacker overwriting a password vault with an
	// age-pubkey vault encrypted to the victim's own public key.
	hdr := &envelopeHeader{Algorithm: "age-pubkey"}
	err := CheckTrust(path, []byte("vault-bytes"), hdr)
	if err == nil {
		t.Fatal("expected trust check to fail on algorithm mismatch")
	}
	if err == ErrUntrustedVault {
		t.Fatalf("expected a mismatch error, got ErrUntrustedVault")
	}
}

func TestCheckTrustRecipientMismatchFails(t *testing.T) {
	withTempHome(t)

	path := "/tmp/shared.env.vault"
	if err := SetTrust(path, TrustRecord{
		Algorithm:  "age-pubkey",
		Recipients: []string{"age1legituser"},
	}); err != nil {
		t.Fatalf("SetTrust: %v", err)
	}

	hdr := &envelopeHeader{
		Algorithm: "age-pubkey",
		ProviderParams: map[string]any{
			"recipients": []any{"age1attacker"},
		},
	}

	if err := CheckTrust(path, []byte("vault-bytes"), hdr); err == nil {
		t.Fatal("expected trust check to fail on recipient mismatch")
	}
}

func TestCheckTrustRecipientMatchPasses(t *testing.T) {
	withTempHome(t)

	path := "/tmp/shared-ok.env.vault"
	if err := SetTrust(path, TrustRecord{
		Algorithm:  "age-pubkey",
		Recipients: []string{"age1legituser"},
	}); err != nil {
		t.Fatalf("SetTrust: %v", err)
	}

	hdr := &envelopeHeader{
		Algorithm: "age-pubkey",
		ProviderParams: map[string]any{
			"recipients": []any{"age1legituser"},
		},
	}

	if err := CheckTrust(path, []byte("vault-bytes"), hdr); err != nil {
		t.Fatalf("expected trust check to pass, got %v", err)
	}
}

func TestCheckTrustContentSubstitutionFails(t *testing.T) {
	withTempHome(t)

	path := "/tmp/content-pinned.env.vault"
	original := []byte("original-vault-bytes")
	if err := SetTrust(path, TrustRecord{
		Algorithm: "age-pubkey",
		Checksum:  HashVaultChecksum(original),
	}); err != nil {
		t.Fatalf("SetTrust: %v", err)
	}

	// Same algorithm, same (public) recipients, but different ciphertext —
	// exactly what an attacker without the vault owner's key can produce
	// for an age-pubkey vault, since encryption only needs the recipient's
	// public key.
	substituted := []byte("attacker-substituted-bytes")
	hdr := &envelopeHeader{Algorithm: "age-pubkey"}

	err := CheckTrust(path, substituted, hdr)
	if err == nil {
		t.Fatal("expected trust check to fail on content substitution")
	}
	if err == ErrUntrustedVault {
		t.Fatalf("expected a mismatch error, got ErrUntrustedVault")
	}
}

func TestCheckTrustContentMatchPasses(t *testing.T) {
	withTempHome(t)

	path := "/tmp/content-pinned-ok.env.vault"
	vaultBytes := []byte("the-actual-vault-bytes")
	if err := SetTrust(path, TrustRecord{
		Algorithm: "age-pubkey",
		Checksum:  HashVaultChecksum(vaultBytes),
	}); err != nil {
		t.Fatalf("SetTrust: %v", err)
	}

	hdr := &envelopeHeader{Algorithm: "age-pubkey"}
	if err := CheckTrust(path, vaultBytes, hdr); err != nil {
		t.Fatalf("expected trust check to pass, got %v", err)
	}
}

func TestCheckTrustSkipsContentCheckWhenChecksumNotPinned(t *testing.T) {
	withTempHome(t)

	// Records created before Checksum existed, or via `trust --algorithm`
	// pre-registration, have no pinned checksum — content checking should
	// be skipped, not treated as a mismatch.
	path := "/tmp/no-checksum.env.vault"
	if err := SetTrust(path, TrustRecord{Algorithm: "aesgcm-argon2id"}); err != nil {
		t.Fatalf("SetTrust: %v", err)
	}

	hdr := &envelopeHeader{Algorithm: "aesgcm-argon2id"}
	if err := CheckTrust(path, []byte("anything at all"), hdr); err != nil {
		t.Fatalf("expected trust check to pass without a pinned checksum, got %v", err)
	}
}

func TestClearTrustRemovesRecord(t *testing.T) {
	withTempHome(t)

	path := "/tmp/toclear.env.vault"
	if err := SetTrust(path, TrustRecord{Algorithm: "aesgcm-argon2id"}); err != nil {
		t.Fatalf("SetTrust: %v", err)
	}

	if err := ClearTrust(path); err != nil {
		t.Fatalf("ClearTrust: %v", err)
	}

	if _, ok, err := GetTrust(path); err != nil || ok {
		t.Fatalf("expected no trust record after clear, ok=%v err=%v", ok, err)
	}
}

func TestRelativePathsResolveToSameTrustRecord(t *testing.T) {
	withTempHome(t)

	dir := t.TempDir()
	t.Chdir(dir)

	if err := SetTrust(".env.vault", TrustRecord{Algorithm: "aesgcm-argon2id"}); err != nil {
		t.Fatalf("SetTrust: %v", err)
	}

	hdr := &envelopeHeader{Algorithm: "aesgcm-argon2id"}
	if err := CheckTrust(".env.vault", []byte("vault-bytes"), hdr); err != nil {
		t.Fatalf("expected trust check to pass for relative path, got %v", err)
	}
}
