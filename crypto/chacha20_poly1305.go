package crypto

import (
	"crypto/subtle"
	"encoding/binary"
	"errors"

	"golang.org/x/crypto/chacha20poly1305"
)

type ChaCha20Poly1305Provider struct {
	ID string
}

func (c *ChaCha20Poly1305Provider) AlgorithmID() string {
	return c.ID
}

func (c *ChaCha20Poly1305Provider) Encrypt(plaintext, password []byte) ([]byte, error) {
	if len(password) == 0 {
		return nil, ErrInvalidPassword
	}

	nonce, err := RandomBytes(chacha20poly1305.NonceSize)
	if err != nil {
		return nil, err
	}

	salt, err := RandomBytes(16)
	if err != nil {
		return nil, err
	}

	key := DeriveKey(password, salt, 3, 64*1024, 4)
	defer secureWipe(key)

	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	// Seal appends the tag to the ciphertext, matching this provider's
	// existing on-disk format: [Salt (16)] [Nonce (12)] [Ciphertext] [Tag (16)].
	ciphertextAndTag := aead.Seal(nil, nonce, plaintext, nil)

	output := make([]byte, 0, 16+12+len(ciphertextAndTag))
	output = append(output, salt...)
	output = append(output, nonce...)
	output = append(output, ciphertextAndTag...)

	return output, nil
}

func (c *ChaCha20Poly1305Provider) Decrypt(payload, password []byte) ([]byte, error) {
	if len(password) == 0 {
		return nil, ErrInvalidPassword
	}

	if len(payload) < 16+12+16 {
		return nil, ErrInvalidPayload
	}

	salt := payload[:16]
	nonce := payload[16:28]
	ciphertextAndTag := payload[28:]

	key := DeriveKey(password, salt, 3, 64*1024, 4)
	defer secureWipe(key)

	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}

	if plaintext, err := aead.Open(nil, nonce, ciphertextAndTag, nil); err == nil {
		return plaintext, nil
	}

	// Fall back to the original hand-rolled construction. Its Poly1305 MAC
	// has a real bug (its tags don't match RFC 8439 test vectors — see the
	// deprecation note on poly1305Tag below), so vaults this provider
	// encrypted before the switch to the vetted AEAD above have tags the
	// standard implementation will always reject. This keeps them
	// decryptable; Encrypt above never produces this format anymore.
	if plaintext, ok := c.legacyDecrypt(ciphertextAndTag, key, nonce); ok {
		return plaintext, nil
	}

	return nil, errors.New("authentication failed")
}

// legacyDecrypt verifies and decrypts a payload using the original
// hand-rolled ChaCha20+Poly1305 construction, for backward compatibility
// with vaults encrypted before Encrypt switched to the vetted
// golang.org/x/crypto/chacha20poly1305 AEAD.
func (c *ChaCha20Poly1305Provider) legacyDecrypt(ciphertextAndTag, key, nonce []byte) ([]byte, bool) {
	if len(ciphertextAndTag) < 16 {
		return nil, false
	}
	tag := ciphertextAndTag[len(ciphertextAndTag)-16:]
	ciphertext := ciphertextAndTag[:len(ciphertextAndTag)-16]

	block0KeyStream := generateKeyStream(key, nonce, 0)
	var polyKey [32]byte
	copy(polyKey[:], block0KeyStream[:32])

	if !poly1305Verify(polyKey, ciphertext, tag) {
		return nil, false
	}

	plaintext := make([]byte, len(ciphertext))
	for i := 0; i < len(ciphertext); i += 64 {
		end := min(i+64, len(ciphertext))
		blockCount := uint32((i / 64) + 1)
		keyStream := generateKeyStream(key, nonce, blockCount)
		for j := i; j < end; j++ {
			plaintext[j] = ciphertext[j] ^ keyStream[j-i]
		}
	}

	return plaintext, true
}

func (c *ChaCha20Poly1305Provider) Description() ProviderInfo {
	return ProviderInfo{
		ID:          c.ID,
		Description: "An authenticated encryption scheme combining ChaCha20 stream cipher with Poly1305 MAC for integrity.",
		Secure:      true,
	}
}

// poly1305Tag and poly1305Verify below are the original hand-rolled
// Poly1305 MAC (RFC 8439). Encrypt now uses the vetted
// golang.org/x/crypto/chacha20poly1305 AEAD instead of this from-scratch
// construction, and Decrypt only falls back to these (via legacyDecrypt)
// for vaults encrypted before that switch.
//
// poly1305Tag does NOT match RFC 8439's test vectors — it has a genuine
// carry-propagation bug — so its tags are only self-consistent with this
// file's own poly1305Verify, not interoperable with any standard Poly1305
// implementation. That's fine for its current sole purpose (decrypting
// envvault's own legacy ciphertexts), but do not reuse it anywhere a
// standards-compliant tag is required.
//
// Deprecated: superseded by golang.org/x/crypto/chacha20poly1305 for new
// encryption; only legacyDecrypt should still call this.
func poly1305Tag(key [32]byte, message []byte) [16]byte {
	r := make([]byte, 16)
	copy(r, key[:16])
	r[3] &= 15
	r[7] &= 15
	r[11] &= 15
	r[15] &= 15
	r[4] &= 252
	r[8] &= 252
	r[12] &= 252

	s := key[16:32]

	r0 := uint64(binary.LittleEndian.Uint32(r[0:4])) & 0x3ffffff
	r1 := (uint64(binary.LittleEndian.Uint32(r[3:7])) >> 2) & 0x3ffffff
	r2 := (uint64(binary.LittleEndian.Uint32(r[6:10])) >> 4) & 0x3ffffff
	r3 := (uint64(binary.LittleEndian.Uint32(r[9:13])) >> 6) & 0x3ffffff
	r4 := (uint64(binary.LittleEndian.Uint32(r[12:16])) >> 8) & 0x3ffffff

	s1 := r1 * 5
	s2 := r2 * 5
	s3 := r3 * 5
	s4 := r4 * 5

	var a0, a1, a2, a3, a4 uint64

	for len(message) > 0 {
		block := message
		if len(block) > 16 {
			block = block[:16]
		}

		var padded [17]byte
		copy(padded[:], block)
		padded[len(block)] = 1

		m0 := uint64(binary.LittleEndian.Uint32(padded[0:4]))
		m1 := uint64(binary.LittleEndian.Uint32(padded[4:8]))
		m2 := uint64(binary.LittleEndian.Uint32(padded[8:12]))
		m3 := uint64(binary.LittleEndian.Uint32(padded[12:16]))
		m4 := uint64(padded[16])

		b0 := m0 & 0x3ffffff
		b1 := ((m0 >> 26) | (m1 << 6)) & 0x3ffffff
		b2 := ((m1 >> 20) | (m2 << 12)) & 0x3ffffff
		b3 := ((m2 >> 14) | (m3 << 18)) & 0x3ffffff
		b4 := ((m3 >> 8) | (m4 << 24)) & 0x3ffffff

		a0 += b0
		a1 += b1
		a2 += b2
		a3 += b3
		a4 += b4

		d0 := a0*r0 + a1*s4 + a2*s3 + a3*s2 + a4*s1
		d1 := a0*r1 + a1*r0 + a2*s4 + a3*s3 + a4*s2
		d2 := a0*r2 + a1*r1 + a2*r0 + a3*s4 + a4*s3
		d3 := a0*r3 + a1*r2 + a2*r1 + a3*r0 + a4*s4
		d4 := a0*r4 + a1*r3 + a2*r2 + a3*r1 + a4*r0

		a0 = d0 & 0x3ffffff
		carry := d0 >> 26
		d1 += carry
		a1 = d1 & 0x3ffffff
		carry = d1 >> 26
		d2 += carry
		a2 = d2 & 0x3ffffff
		carry = d2 >> 26
		d3 += carry
		a3 = d3 & 0x3ffffff
		carry = d3 >> 26
		d4 += carry
		a4 = d4 & 0x3ffffff
		carry = d4 >> 26
		a0 += carry * 5

		carry = a0 >> 26
		a0 &= 0x3ffffff
		a1 += carry
		carry = a1 >> 26
		a1 &= 0x3ffffff
		a2 += carry
		carry = a2 >> 26
		a2 &= 0x3ffffff
		a3 += carry
		carry = a3 >> 26
		a3 &= 0x3ffffff
		a4 += carry
		carry = a4 >> 26
		a4 &= 0x3ffffff
		a0 += carry * 5

		carry = a0 >> 26
		a0 &= 0x3ffffff
		a1 += carry

		message = message[len(block):]
	}

	t0 := a0 | (a1 << 26)
	t1 := (a1 >> 6) | (a2 << 20)
	t2 := (a2 >> 12) | (a3 << 14)
	t3 := (a3 >> 18) | (a4 << 8)

	s0 := uint64(binary.LittleEndian.Uint32(s[0:4]))
	s1v := uint64(binary.LittleEndian.Uint32(s[4:8]))
	s2v := uint64(binary.LittleEndian.Uint32(s[8:12]))
	s3v := uint64(binary.LittleEndian.Uint32(s[12:16]))

	t0 += s0
	t1 += s1v + (t0 >> 32)
	t2 += s2v + (t1 >> 32)
	t3 += s3v + (t2 >> 32)

	var tag [16]byte
	binary.LittleEndian.PutUint32(tag[0:4], uint32(t0&0xffffffff))
	binary.LittleEndian.PutUint32(tag[4:8], uint32(t1&0xffffffff))
	binary.LittleEndian.PutUint32(tag[8:12], uint32(t2&0xffffffff))
	binary.LittleEndian.PutUint32(tag[12:16], uint32(t3&0xffffffff))

	return tag
}

func poly1305Verify(key [32]byte, message, tag []byte) bool {
	if len(tag) != 16 {
		return false
	}

	expected := poly1305Tag(key, message)
	return subtle.ConstantTimeCompare(expected[:], tag) == 1
}

func init() {
	if err := Register(&ChaCha20Poly1305Provider{ID: "chacha20poly1305"}); err != nil {
		panic(err)
	}
}
