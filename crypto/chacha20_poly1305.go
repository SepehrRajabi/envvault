package crypto

import (
	"crypto/subtle"
	"encoding/binary"
	"errors"
)

type ChaCha20Poly1305Provider struct{}

func (c *ChaCha20Poly1305Provider) AlgorithmID() string {
	return "chacha20poly1305"
}

func (c *ChaCha20Poly1305Provider) Encrypt(plaintext, password []byte) ([]byte, error) {
	if len(password) == 0 {
		return nil, ErrInvalidPassword
	}

	nonce, err := RandomBytes(12)
	if err != nil {
		return nil, err
	}

	salt, err := RandomBytes(16)
	if err != nil {
		return nil, err
	}

	key := DeriveKey(password, salt, 3, 64*1024, 4)
	defer secureWipe(key)

	block0KeyStream := generateKeyStream(key, nonce, 0)
	var polyKey [32]byte
	copy(polyKey[:], block0KeyStream[:32])

	ciphertext := make([]byte, len(plaintext))
	for i := 0; i < len(plaintext); i += 64 {
		end := min(i+64, len(plaintext))

		blockCount := uint32((i / 64) + 1)
		keyStream := generateKeyStream(key, nonce, blockCount)

		for j := i; j < end; j++ {
			ciphertext[j] = plaintext[j] ^ keyStream[j-i]
		}
	}

	tag := poly1305Tag(polyKey, ciphertext)

	output := make([]byte, 0, 16+12+len(ciphertext)+16)
	output = append(output, salt...)
	output = append(output, nonce...)
	output = append(output, ciphertext...)
	output = append(output, tag[:]...)

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
	tag := payload[len(payload)-16:]
	ciphertext := payload[28 : len(payload)-16]

	key := DeriveKey(password, salt, 3, 64*1024, 4)
	defer secureWipe(key)

	block0KeyStream := generateKeyStream(key, nonce, 0)
	var polyKey [32]byte
	copy(polyKey[:], block0KeyStream[:32])

	if !poly1305Verify(polyKey, ciphertext, tag) {
		return nil, errors.New("authentication failed")
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

	return plaintext, nil
}

func (c *ChaCha20Poly1305Provider) Description() ProviderInfo {
	return ProviderInfo{
		ID:          "ChaCha20-Poly1305",
		Description: "An authenticated encryption scheme combining ChaCha20 stream cipher with Poly1305 MAC for integrity.",
		Secure:      true,
	}
}

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
	Register(&ChaCha20Poly1305Provider{})
}
