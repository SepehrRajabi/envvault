package crypto

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"testing"
)

func hdrOf(t *testing.T, vault []byte) *envelopeHeader {
	t.Helper()
	h, _, err := parseEnvelope(vault)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// rebuild re-serializes a vault with a modified header and original payload.
func rebuild(t *testing.T, vault []byte, mutate func(*envelopeHeader)) []byte {
	t.Helper()
	h, payload, err := parseEnvelope(vault)
	if err != nil {
		t.Fatal(err)
	}
	mutate(h)
	hj, _ := json.Marshal(h)
	out := []byte{vault[0]}
	out = binary.BigEndian.AppendUint32(out, uint32(len(hj)))
	out = append(out, hj...)
	return append(out, payload...)
}

func TestHeaderChecksumDoesNotRevealPlaintextHash(t *testing.T) {
	pt := []byte("PIN=1234\n")
	v, err := Encrypt(pt, []byte("pw-for-test-1"))
	if err != nil {
		t.Fatal(err)
	}
	h := hdrOf(t, v)
	if h.Version != currentVersion {
		t.Fatalf("version = %d, want %d", h.Version, currentVersion)
	}
	sum := sha256.Sum256(pt)
	if h.Checksum == hex.EncodeToString(sum[:]) {
		t.Fatal("header checksum is an unkeyed SHA-256 of the plaintext")
	}
	// Same plaintext, same password: tags must differ (per-vault random key).
	v2, _ := Encrypt(pt, []byte("pw-for-test-1"))
	if hdrOf(t, v2).Checksum == h.Checksum {
		t.Fatal("checksum is deterministic across encryptions of the same plaintext")
	}
	got, err := Decrypt(v, []byte("pw-for-test-1"), nil)
	if err != nil || !bytes.Equal(got, pt) {
		t.Fatalf("roundtrip: %q, %v", got, err)
	}
}

func TestLegacyV1VaultStillDecrypts(t *testing.T) {
	pt := []byte("OLD=vault\n")
	p, _ := GetProvider("aes256gcm-argon2id")
	payload, err := p.Encrypt(pt, []byte("legacy-pass-1"))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(pt)
	hj, _ := json.Marshal(envelopeHeader{Version: 1, Algorithm: "aes256gcm-argon2id", Checksum: hex.EncodeToString(sum[:])})
	v := []byte{1}
	v = binary.BigEndian.AppendUint32(v, uint32(len(hj)))
	v = append(v, hj...)
	v = append(v, payload...)

	got, err := Decrypt(v, []byte("legacy-pass-1"), nil)
	if err != nil || !bytes.Equal(got, pt) {
		t.Fatalf("legacy decrypt: %q, %v", got, err)
	}
	lb, err := DecryptSecure(v, []byte("legacy-pass-1"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer lb.Unlock()
	if !bytes.Equal(lb.Bytes(), pt) {
		t.Fatalf("legacy DecryptSecure: %q", lb.Bytes())
	}
	if _, err := Verify(v); err != nil {
		t.Fatalf("Verify legacy: %v", err)
	}
}

func TestHeaderTamperingDetected(t *testing.T) {
	pw := []byte("pw-for-test-2")
	v, err := Encrypt([]byte("A=1\n"), pw)
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(*envelopeHeader){
		"params":  func(h *envelopeHeader) { h.ProviderParams = map[string]any{"recipients": []string{"age1evil"}} },
		"commit":  func(h *envelopeHeader) { h.Commit = &GitCommitMetadata{Hash: "deadbeef"} },
		"tag":     func(h *envelopeHeader) { h.Checksum = hex.EncodeToString(make([]byte, 32)) },
		"version": func(h *envelopeHeader) { h.Version = legacyVersion },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			bad := rebuild(t, v, mutate)
			if _, err := Decrypt(bad, pw, nil); err == nil {
				t.Fatal("tampered header accepted")
			}
		})
	}
}

// Unauthenticated ChaCha20: flipping a ciphertext bit and recomputing the old
// kind of plaintext hash must no longer produce an accepted vault.
func TestUnauthenticatedCipherBitFlipDetected(t *testing.T) {
	p, _ := GetProvider("chacha20")
	pw := []byte("pw-for-test-3")
	pt := []byte("ADMIN=false\n")
	v, err := Encrypt(pt, pw, p)
	if err != nil {
		t.Fatal(err)
	}
	h, payload, _ := parseEnvelope(v)
	// Attacker knows the plaintext: flip "false" -> "true " and recompute SHA-256.
	forged := append([]byte(nil), payload...)
	off := 28 + macKeyLen + len("ADMIN=")
	for i, b := range []byte("false") {
		forged[off+i] ^= b ^ []byte("true ")[i]
	}
	newPT := []byte("ADMIN=true \n")
	sum := sha256.Sum256(newPT)
	h.Checksum = hex.EncodeToString(sum[:])
	hj, _ := json.Marshal(h)
	out := []byte{v[0]}
	out = binary.BigEndian.AppendUint32(out, uint32(len(hj)))
	out = append(out, hj...)
	out = append(out, forged...)
	if _, err := Decrypt(out, pw, nil); err == nil {
		t.Fatal("bit-flipped unauthenticated vault accepted")
	}
	if got, err := Decrypt(v, pw, nil); err != nil || !bytes.Equal(got, pt) {
		t.Fatalf("untampered roundtrip: %q, %v", got, err)
	}
}
