package crypto

import "errors"

var (
	ErrProviderNotFound = errors.New("Algorithm not registered")
	ErrInvalidProvider  = errors.New("Invalid Provider ID")
)

type Provider interface {
	// AlgorithmID returns a unique identifier (e.g., "aes256gcm-argon2id", "chacha20poly1305")
	// Rules: lowercase, alphanumeric + hyphens only, max 32 chars.
	AlgorithmID() string

	// Encrypt transforms plaintext into ciphertext using the password.
	// The returned payload should contain everything needed for decryption
	// (salt, nonce, ciphertext, etc.) but NOT the envelope metadata.
	Encrypt(plaintext, password []byte) (payload []byte, err error)

	// Decrypt reverses the encryption. Payload is the raw bytes returned by Encrypt.
	Decrypt(payload, password []byte) (plaintext []byte, err error)

	// Optional description for the encryption.
	Description() ProviderInfo
}

// Netadata about an algorithm
type ProviderInfo struct {
	ID          string
	Description string
	Secure      bool
}
