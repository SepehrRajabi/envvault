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
		ID:       "aes256gcm-argon2id",
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
	ID       string
	Time     uint32
	Memory   uint32
	Threads  uint8
	SaltLen  int
	NonceLen int
}

func (a *AESGCMProvider) AlgorithmID() string {
	return a.ID
}

func (a *AESGCMProvider) Encrypt(plaintext, password []byte) ([]byte, error) {
	salt, nonce, ciphertext, err := encryptAESGCMArgon2(
		plaintext,
		password,
		a.Time,
		a.Memory,
		a.Threads,
		a.SaltLen,
		a.NonceLen,
	)
	if err != nil {
		return nil, err
	}

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

	return decryptAESGCMArgon2(ciphertext, password, salt, nonce, a.Time, a.Memory, a.Threads)
}

func encryptAESGCMArgon2(
	plaintext, password []byte,
	time, memory uint32,
	threads uint8,
	saltLen, nonceLen int,
) (salt, nonce, ciphertext []byte, err error) {
	salt = make([]byte, saltLen)
	if _, err = io.ReadFull(rand.Reader, salt); err != nil {
		return nil, nil, nil, err
	}

	nonce = make([]byte, nonceLen)
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, nil, err
	}

	ciphertext, err = encryptWithDerivedKeyAESGCM(plaintext, password, salt, nonce, time, memory, threads)
	if err != nil {
		return nil, nil, nil, err
	}
	return salt, nonce, ciphertext, nil
}

func decryptAESGCMArgon2(
	ciphertext, password, salt, nonce []byte,
	time, memory uint32,
	threads uint8,
) ([]byte, error) {
	return decryptWithDerivedKeyAESGCM(ciphertext, password, salt, nonce, time, memory, threads)
}

func encryptWithDerivedKeyAESGCM(
	plaintext, password, salt, nonce []byte,
	time, memory uint32,
	threads uint8,
) ([]byte, error) {
	key := argon2.IDKey(password, salt, time, memory, threads, 32)
	defer SecureWipe(key)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	return aead.Seal(nil, nonce, plaintext, nil), nil
}

func decryptWithDerivedKeyAESGCM(
	ciphertext, password, salt, nonce []byte,
	time, memory uint32,
	threads uint8,
) ([]byte, error) {
	key := argon2.IDKey(password, salt, time, memory, threads, 32)
	defer SecureWipe(key)

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
