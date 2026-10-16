package crypto

import (
	"fmt"
)

// DecryptSecure decrypts data and returns plaintext in locked memory.
// The returned LockedBytes must be explicitly unlocked when done.
// This provides stronger protection against memory swapping compared to regular Decrypt.
func DecryptSecure(data, password []byte, p Provider) (*LockedBytes, error) {
	plaintext, raw, _, err := decryptEnvelope(data, password)
	if err != nil {
		return nil, err
	}
	defer SecureWipe(raw)

	lockedPlaintext, err := NewLockedBytesFrom(plaintext)
	if err != nil {
		return nil, fmt.Errorf("failed to lock plaintext in memory: %w", err)
	}
	return lockedPlaintext, nil
}

// DecryptWithPassword is a convenience function that reads the password from stdin,
// decrypts the data, and returns it in locked memory.
func DecryptWithPassword(data []byte, p Provider, promptMessage string) (*LockedBytes, error) {
	if len(promptMessage) == 0 {
		promptMessage = "Enter password: "
	}

	// Read password into a LockedBytes
	password, err := GetPasswordLocked(promptMessage)
	if err != nil {
		return nil, fmt.Errorf("reading password: %w", err)
	}
	defer password.Unlock()

	// Decrypt with the locked password
	return DecryptSecure(data, password.Bytes(), p)
}

// GetPasswordLocked reads a password from the terminal and returns it in locked memory.
// The caller must unlock the LockedBytes when done.
func GetPasswordLocked(prompt string) (*LockedBytes, error) {
	password, err := readPassword(prompt)
	if err != nil {
		return nil, err
	}

	// Move the password into locked memory
	lockedPassword, err := NewLockedBytesFrom(password)
	if err != nil {
		// Securely wipe the plaintext password if locking fails
		SecureWipe(password)
		return nil, fmt.Errorf("failed to lock password in memory: %w", err)
	}

	// Securely wipe the temporary plaintext password
	SecureWipe(password)

	return lockedPassword, nil
}

// DecryptToString decrypts data and returns it as a string.
// WARNING: Strings are immutable in Go and cannot be securely wiped.
// Use DecryptSecure instead when possible.
// The returned data will be vulnerable to memory scraping.
func DecryptToString(data, password []byte, p Provider) (string, error) {
	plaintext, err := Decrypt(data, password, p)
	if err != nil {
		return "", err
	}
	result := string(plaintext)
	SecureWipe(plaintext)
	return result, nil
}

// DecryptAndLock is a helper that decrypts and immediately locks the plaintext,
// then securely wipes the temporary plaintext. This is optimized for the common
// case where you want the result in locked memory.
func DecryptAndLock(data, password []byte, p Provider) (*LockedBytes, error) {
	return DecryptSecure(data, password, p)
}

// BatchDecryptSecure decrypts multiple vault files using a single cached password,
// returning all plaintexts in locked memory. This is more efficient than
// decrypting each file separately with separate password prompts.
func BatchDecryptSecure(vaults [][]byte, password []byte, provider Provider) ([]*LockedBytes, error) {
	results := make([]*LockedBytes, 0, len(vaults))

	for _, vaultData := range vaults {
		plaintext, err := DecryptSecure(vaultData, password, provider)
		if err != nil {
			// Clean up on error: unlock all previously decrypted data
			for _, p := range results {
				p.Unlock() //nolint:errcheck
			}
			return nil, err
		}
		results = append(results, plaintext)
	}

	return results, nil
}

// DecryptedEnv represents a decrypted environment in locked memory with its metadata.
type DecryptedEnv struct {
	Data   *LockedBytes // Locked plaintext
	Header *envelopeHeader
}

// DecryptWithMetadata decrypts data, returns plaintext in locked memory along with envelope metadata.
func DecryptWithMetadata(data, password []byte, p Provider) (*DecryptedEnv, error) {
	plaintext, raw, hdr, err := decryptEnvelope(data, password)
	if err != nil {
		return nil, err
	}
	defer SecureWipe(raw)

	lockedPlaintext, err := NewLockedBytesFrom(plaintext)
	if err != nil {
		return nil, fmt.Errorf("failed to lock plaintext in memory: %w", err)
	}

	return &DecryptedEnv{
		Data: lockedPlaintext,
		Header: &envelopeHeader{
			Version:        hdr.Version,
			Algorithm:      hdr.Algorithm,
			Checksum:       hdr.Checksum,
			ProviderParams: hdr.ProviderParams,
			Commit:         hdr.Commit,
		},
	}, nil
}

// Clean up a DecryptedEnv
func (de *DecryptedEnv) Close() error {
	if de.Data != nil {
		return de.Data.Unlock()
	}
	return nil
}
