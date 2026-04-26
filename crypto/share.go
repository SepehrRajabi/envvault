package crypto

import (
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/SepehrRajabi/envvault/envfile"
)

const (
	// SharePrefix is the prefix for shared variable format
	SharePrefix = "evlt://"
)

// SharedPayload represents the encrypted variables to be shared
type SharedPayload struct {
	// Encrypted data (base64-encoded ciphertext)
	Data string `json:"data"`
	// Algorithm used for encryption
	Algorithm string `json:"algorithm"`
}

// EncodeShare encrypts variables and returns an evlt:// encoded string
func EncodeShare(variables map[string]string, recipientPublicKey string) (string, error) {
	if len(variables) == 0 {
		return "", fmt.Errorf("no variables to share")
	}

	// Serialize variables as JSON
	data, err := json.Marshal(variables)
	if err != nil {
		return "", fmt.Errorf("failed to serialize variables: %w", err)
	}

	// Get Age provider for public key encryption
	provider := &AgeProvider{}

	// Encrypt using the recipient's public key
	encrypted, err := Encrypt(data, []byte(recipientPublicKey), provider)
	if err != nil {
		return "", fmt.Errorf("failed to encrypt: %w", err)
	}

	// Create payload
	payload := SharedPayload{
		Data:      base64.StdEncoding.EncodeToString(encrypted),
		Algorithm: "age-pubkey",
	}

	// Marshal payload to JSON
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("failed to marshal payload: %w", err)
	}

	// Encode as base64 and add prefix
	encoded := base64.StdEncoding.EncodeToString(payloadJSON)
	return SharePrefix + encoded, nil
}

// DecodeShare decrypts an evlt:// encoded string
func DecodeShare(sharedString string) (map[string]string, error) {
	// Remove prefix
	if len(sharedString) < len(SharePrefix) || sharedString[:len(SharePrefix)] != SharePrefix {
		return nil, fmt.Errorf("invalid share format: must start with %s", SharePrefix)
	}

	encoded := sharedString[len(SharePrefix):]

	// Decode from base64
	payloadJSON, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("failed to decode share: %w", err)
	}

	// Unmarshal payload
	var payload SharedPayload
	if err := json.Unmarshal(payloadJSON, &payload); err != nil {
		return nil, fmt.Errorf("failed to unmarshal payload: %w", err)
	}

	// Decode data from base64
	encrypted, err := base64.StdEncoding.DecodeString(payload.Data)
	if err != nil {
		return nil, fmt.Errorf("failed to decode encrypted data: %w", err)
	}

	// Decrypt using Age provider
	provider := &AgeProvider{}
	decrypted, err := Decrypt(encrypted, []byte{}, provider)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %w", err)
	}

	// Unmarshal variables
	var variables map[string]string
	if err := json.Unmarshal(decrypted, &variables); err != nil {
		return nil, fmt.Errorf("failed to unmarshal variables: %w", err)
	}

	return variables, nil
}

// FilterVariables filters environment variables by name or wildcard pattern
func FilterVariables(envVars []envfile.EnvVar, filters []string) map[string]string {
	result := make(map[string]string)

	for _, filter := range filters {
		for _, envVar := range envVars {
			if matchesPattern(envVar.Key, filter) {
				result[envVar.Key] = envVar.Value
			}
		}
	}

	return result
}

// matchesPattern checks if a key matches a filter pattern (supports * wildcard)
func matchesPattern(key, pattern string) bool {
	// Simple wildcard matching
	if pattern == "*" {
		return true
	}

	if pattern == key {
		return true
	}

	// Handle * wildcard
	if len(pattern) > 0 && pattern[len(pattern)-1] == '*' {
		prefix := pattern[:len(pattern)-1]
		return len(key) >= len(prefix) && key[:len(prefix)] == prefix
	}

	return false
}
