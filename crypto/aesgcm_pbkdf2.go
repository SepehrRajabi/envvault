package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/crypto/pbkdf2"
)

const aesgcmpkbdf2Version = 1

func init() {
	// Register PBKDF2-based AES-256-GCM provider
	pbkdf2Provider := &AESGCMPbkdf2Provider{
		ID:         "aes256gcm-pbkdf2",
		Iterations: 600000,
		SaltLen:    32,
		NonceLen:   12,
	}
	Register(pbkdf2Provider)
}

// AESGCMPbkdf2Provider implements AES-256-GCM with PBKDF2 key derivation.
type AESGCMPbkdf2Provider struct {
	ID         string
	Iterations int
	SaltLen    int
	NonceLen   int
}

func (a *AESGCMPbkdf2Provider) AlgorithmID() string {
	return a.ID
}

func (a *AESGCMPbkdf2Provider) Encrypt(plaintext, password []byte) ([]byte, error) {
	salt, nonce, ciphertext, err := encryptAESGCMPbkdf2(
		plaintext,
		password,
		a.Iterations,
		a.SaltLen,
		a.NonceLen,
	)
	if err != nil {
		return nil, err
	}

	// Payload format: [version][salt][nonce][ciphertext]
	// Since salt/nonce lengths are fixed by provider params, we don't need length prefixes
	payload := make([]byte, 0, 1+len(salt)+len(nonce)+len(ciphertext))
	payload = append(payload, aesgcmpkbdf2Version)
	payload = append(payload, salt...)
	payload = append(payload, nonce...)
	payload = append(payload, ciphertext...)

	return payload, nil
}

func (a *AESGCMPbkdf2Provider) Decrypt(payload, password []byte) ([]byte, error) {
	if len(payload) < 1+a.SaltLen+a.NonceLen {
		return nil, fmt.Errorf("payload too small")
	}

	version := payload[0]
	if version != aesgcmpkbdf2Version {
		return nil, fmt.Errorf("unsupported version: got %d want %d", version, aesgcmpkbdf2Version)
	}

	salt := payload[1 : 1+a.SaltLen]
	nonce := payload[1+a.SaltLen : 1+a.SaltLen+a.NonceLen]
	ciphertext := payload[1+a.SaltLen+a.NonceLen:]

	return decryptAESGCMPbkdf2(ciphertext, password, salt, nonce, a.Iterations)
}

func (a *AESGCMPbkdf2Provider) Description() ProviderInfo {
	return ProviderInfo{
		ID:          a.AlgorithmID(),
		Description: "AES-256-GCM with PBKDF2 key derivation",
		Secure:      true,
	}
}

func encryptAESGCMPbkdf2(
	plaintext, password []byte,
	iterations, saltLen, nonceLen int,
) (salt, nonce, ciphertext []byte, err error) {
	salt = make([]byte, saltLen)
	if _, err = io.ReadFull(rand.Reader, salt); err != nil {
		return nil, nil, nil, err
	}

	nonce = make([]byte, nonceLen)
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, nil, err
	}

	ciphertext, err = encryptWithDerivedKeyAESGCMPbkdf2(plaintext, password, salt, nonce, iterations)
	if err != nil {
		return nil, nil, nil, err
	}
	return salt, nonce, ciphertext, nil
}

func decryptAESGCMPbkdf2(
	ciphertext, password, salt, nonce []byte,
	iterations int,
) ([]byte, error) {
	return decryptWithDerivedKeyAESGCMPbkdf2(ciphertext, password, salt, nonce, iterations)
}

func encryptWithDerivedKeyAESGCMPbkdf2(
	plaintext, password, salt, nonce []byte,
	iterations int,
) ([]byte, error) {
	// Derive a 32-byte key (256-bit) using PBKDF2 with SHA-256
	key := pbkdf2.Key(password, salt, iterations, 32, sha256.New)
	defer SecureWipe(key)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	if len(nonce) != aead.NonceSize() {
		return nil, fmt.Errorf("invalid nonce size: got %d want %d", len(nonce), aead.NonceSize())
	}

	return aead.Seal(nil, nonce, plaintext, nil), nil
}

func decryptWithDerivedKeyAESGCMPbkdf2(
	ciphertext, password, salt, nonce []byte,
	iterations int,
) ([]byte, error) {
	// Derive the same 32-byte key (256-bit) using PBKDF2 with SHA-256
	key := pbkdf2.Key(password, salt, iterations, 32, sha256.New)
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
