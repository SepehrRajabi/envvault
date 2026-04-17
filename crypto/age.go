package crypto

import (
	"bytes"
	"fmt"

	"filippo.io/age"
)

type AgeProvider struct{}

func (a *AgeProvider) AlgorithmID() string {
	return "age-passphrase"
}

func (a *AgeProvider) Encrypt(plaintext, password []byte) ([]byte, error) {
	if len(password) == 0 {
		return nil, fmt.Errorf("password cannot be empty")
	}

	// Create an age recipient from the passphrase
	recipient, err := age.NewScryptRecipient(string(password))
	if err != nil {
		return nil, fmt.Errorf("creating age recipient: %w", err)
	}

	// Buffer to hold the encrypted output
	var buf bytes.Buffer

	// Create the encryption writer
	w, err := age.Encrypt(&buf, recipient)
	if err != nil {
		return nil, fmt.Errorf("initializing age encryption: %w", err)
	}

	// Write the plaintext to the encryption writer
	if _, err := w.Write(plaintext); err != nil {
		return nil, fmt.Errorf("writing plaintext to age: %w", err)
	}

	// Close the writer to flush the encryption stream
	if err := w.Close(); err != nil {
		return nil, fmt.Errorf("closing age encryption stream: %w", err)
	}

	return buf.Bytes(), nil
}

func (a *AgeProvider) Decrypt(payload, password []byte) ([]byte, error) {
	if len(password) == 0 {
		return nil, fmt.Errorf("password cannot be empty")
	}

	// Create an age identity from the passphrase
	identity, err := age.NewScryptIdentity(string(password))
	if err != nil {
		return nil, fmt.Errorf("creating age identity: %w", err)
	}

	// Create a reader for the encrypted payload
	payloadReader := bytes.NewReader(payload)

	// Create the decryption reader
	r, err := age.Decrypt(payloadReader, identity)
	if err != nil {
		return nil, fmt.Errorf("decryption failed (wrong password?): %w", err)
	}

	// Read all decrypted bytes
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(r); err != nil {
		return nil, fmt.Errorf("reading decrypted data: %w", err)
	}

	return buf.Bytes(), nil
}

func (a *AgeProvider) Description() ProviderInfo {
	return ProviderInfo{
		ID:          "age (scrypt passphrase mode)",
		Description: "Uses the age encryption tool with a passphrase. Highly secure and widely used for file encryption.",
		Secure:      true,
	}
}

func init() {
	Register(&AgeProvider{})
}
