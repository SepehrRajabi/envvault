package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"

	"golang.org/x/crypto/argon2"
)

func init() {
	// Register the default implementation
	defaultAES := &AESGCMProvider{
		Time:     3,
		Memory:   64 * 1024,
		Threads:  4,
		SaltLen:  32,
		NonceLen: 12,
	}
	Register(defaultAES)
}

// AESGCMProvider implements AES-256-GCM with Argon2id key derivation.
type AESGCMProvider struct {
	Time     uint32
	Memory   uint32
	Threads  uint8
	SaltLen  int
	NonceLen int
}

func (a *AESGCMProvider) AlgorithmID() string {
	return "aes256gcm-argon2id"
}

func (a *AESGCMProvider) Encrypt(plaintext, password []byte) ([]byte, error) {
	salt := make([]byte, a.SaltLen)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}

	nonce := make([]byte, a.NonceLen)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	key := argon2.IDKey(password, salt, a.Time, a.Memory, a.Threads, 32)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	ciphertext := aead.Seal(nil, nonce, plaintext, nil)

	// Payload format: [salt][nonce][ciphertext]
	// Since salt/nonce lengths are fixed by provider params, we don't need length prefixes
	payload := make([]byte, 0, len(salt)+len(nonce)+len(ciphertext))
	payload = append(payload, salt...)
	payload = append(payload, nonce...)
	payload = append(payload, ciphertext...)

	return payload, nil
}

func (a *AESGCMProvider) Decrypt(payload, password []byte) ([]byte, error) {
	if len(payload) < a.SaltLen+a.NonceLen {
		return nil, fmt.Errorf("payload too small")
	}

	salt := payload[:a.SaltLen]
	nonce := payload[a.SaltLen : a.SaltLen+a.NonceLen]
	ciphertext := payload[a.SaltLen+a.NonceLen:]

	key := argon2.IDKey(password, salt, a.Time, a.Memory, a.Threads, 32)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	return aead.Open(nil, nonce, ciphertext, nil)
}

func (a *AESGCMProvider) Description() ProviderInfo {
	return ProviderInfo{
		ID:          a.AlgorithmID(),
		Description: a.AlgorithmID(),
		Secure:      true,
	}
}
