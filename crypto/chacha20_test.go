package crypto

import (
	"bytes"
	"testing"
)

func TestChaCha20ProviderEncryptDecryptRoundTrip(t *testing.T) {
	p := &ChaCha20Provider{}
	plaintext := []byte("KEY=super-secret-value\n")

	ciphertext, err := p.Encrypt(plaintext, []byte("password123"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	got, err := p.Decrypt(ciphertext, []byte("password123"))
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("expected %q, got %q", plaintext, got)
	}
}

func TestChaCha20ProviderDecryptWithWrongPasswordDoesNotMatch(t *testing.T) {
	p := &ChaCha20Provider{}
	plaintext := []byte("secret data")

	ciphertext, err := p.Encrypt(plaintext, []byte("right-password"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	// ChaCha20Provider is unauthenticated: a wrong password "decrypts"
	// without error, just to garbage. It should not reproduce the
	// original plaintext.
	got, err := p.Decrypt(ciphertext, []byte("wrong-password"))
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if bytes.Equal(got, plaintext) {
		t.Fatal("expected wrong password to fail to reproduce the original plaintext")
	}
}

func TestChaCha20ProviderRejectsEmptyPasswordAndShortPayload(t *testing.T) {
	p := &ChaCha20Provider{}
	if _, err := p.Encrypt([]byte("data"), nil); err != ErrInvalidPassword {
		t.Fatalf("expected ErrInvalidPassword, got %v", err)
	}
	if _, err := p.Decrypt([]byte{1, 2, 3}, []byte("pw")); err != ErrInvalidPayload {
		t.Fatalf("expected ErrInvalidPayload, got %v", err)
	}
}

// TestChaCha20ProviderDecryptsLegacyHandRolledCiphertext proves the switch
// to golang.org/x/crypto/chacha20 is wire-compatible with vaults already
// encrypted by the original hand-rolled implementation (still present,
// unused, in this file as generateKeyStream et al.): both are RFC 8439
// ChaCha20 with a zero-based block counter, salt/nonce in the same layout.
func TestChaCha20ProviderDecryptsLegacyHandRolledCiphertext(t *testing.T) {
	plaintext := []byte("legacy plaintext KEY=value\n")
	password := []byte("legacy-password")
	salt := bytes.Repeat([]byte{0x11}, 16)
	nonce := bytes.Repeat([]byte{0x22}, 12)

	key := DeriveKey(password, salt, 3, 64*1024, 4)
	legacyCiphertext := make([]byte, len(plaintext))
	for i := 0; i < len(plaintext); i += 64 {
		end := min(i+64, len(plaintext))
		keyStream := generateKeyStream(key, nonce, uint32(i/64))
		for j := i; j < end; j++ {
			legacyCiphertext[j] = plaintext[j] ^ keyStream[j-i]
		}
	}

	payload := make([]byte, 0, 16+12+len(legacyCiphertext))
	payload = append(payload, salt...)
	payload = append(payload, nonce...)
	payload = append(payload, legacyCiphertext...)

	p := &ChaCha20Provider{}
	got, err := p.Decrypt(payload, password)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("expected %q, got %q", plaintext, got)
	}
}

func TestChaCha20Poly1305ProviderEncryptDecryptRoundTrip(t *testing.T) {
	p := &ChaCha20Poly1305Provider{ID: "chacha20poly1305"}
	plaintext := []byte("KEY=super-secret-value\n")

	ciphertext, err := p.Encrypt(plaintext, []byte("password123"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	got, err := p.Decrypt(ciphertext, []byte("password123"))
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("expected %q, got %q", plaintext, got)
	}
}

func TestChaCha20Poly1305ProviderRejectsTamperedCiphertext(t *testing.T) {
	p := &ChaCha20Poly1305Provider{ID: "chacha20poly1305"}
	ciphertext, err := p.Encrypt([]byte("data"), []byte("password123"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	tampered := bytes.Clone(ciphertext)
	tampered[len(tampered)-1] ^= 0xFF

	if _, err := p.Decrypt(tampered, []byte("password123")); err == nil {
		t.Fatal("expected tampered ciphertext to fail authentication")
	}
}

func TestChaCha20Poly1305ProviderRejectsWrongPassword(t *testing.T) {
	p := &ChaCha20Poly1305Provider{ID: "chacha20poly1305"}
	ciphertext, err := p.Encrypt([]byte("data"), []byte("right-password"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	if _, err := p.Decrypt(ciphertext, []byte("wrong-password")); err == nil {
		t.Fatal("expected wrong password to fail authentication")
	}
}

func TestChaCha20Poly1305ProviderRejectsEmptyPasswordAndShortPayload(t *testing.T) {
	p := &ChaCha20Poly1305Provider{ID: "chacha20poly1305"}
	if _, err := p.Encrypt([]byte("data"), nil); err != ErrInvalidPassword {
		t.Fatalf("expected ErrInvalidPassword, got %v", err)
	}
	if _, err := p.Decrypt([]byte{1, 2, 3}, []byte("pw")); err != ErrInvalidPayload {
		t.Fatalf("expected ErrInvalidPayload, got %v", err)
	}
}

// TestChaCha20Poly1305ProviderDecryptsLegacyHandRolledCiphertext proves the
// switch to golang.org/x/crypto/chacha20poly1305 is wire-compatible with
// vaults already encrypted by the original hand-rolled AEAD construction
// (still present, unused, in this file as poly1305Tag et al.): both derive
// the Poly1305 key from ChaCha20 block 0 and encrypt starting at block 1,
// per RFC 8439's AEAD_CHACHA20_POLY1305.
func TestChaCha20Poly1305ProviderDecryptsLegacyHandRolledCiphertext(t *testing.T) {
	plaintext := []byte("legacy plaintext KEY=value\n")
	password := []byte("legacy-password")
	salt := bytes.Repeat([]byte{0x33}, 16)
	nonce := bytes.Repeat([]byte{0x44}, 12)

	key := DeriveKey(password, salt, 3, 64*1024, 4)
	block0KeyStream := generateKeyStream(key, nonce, 0)
	var polyKey [32]byte
	copy(polyKey[:], block0KeyStream[:32])

	legacyCiphertext := make([]byte, len(plaintext))
	for i := 0; i < len(plaintext); i += 64 {
		end := min(i+64, len(plaintext))
		keyStream := generateKeyStream(key, nonce, uint32(i/64)+1)
		for j := i; j < end; j++ {
			legacyCiphertext[j] = plaintext[j] ^ keyStream[j-i]
		}
	}
	tag := poly1305Tag(polyKey, legacyCiphertext)

	payload := make([]byte, 0, 16+12+len(legacyCiphertext)+16)
	payload = append(payload, salt...)
	payload = append(payload, nonce...)
	payload = append(payload, legacyCiphertext...)
	payload = append(payload, tag[:]...)

	p := &ChaCha20Poly1305Provider{ID: "chacha20poly1305"}
	got, err := p.Decrypt(payload, password)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("expected %q, got %q", plaintext, got)
	}
}
