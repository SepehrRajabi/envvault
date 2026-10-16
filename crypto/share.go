package crypto

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/SepehrRajabi/envvault/envfile"
)

const (
	// SharePrefix is the prefix for shared variable format
	SharePrefix = "evlt://"
)

// SharedPayload is the outer, unauthenticated wrapper of an evlt:// string.
// Anything security-relevant (the variables and their expiry) lives inside
// the encrypted envelope instead; see sharedContents.
type SharedPayload struct {
	// Encrypted data (base64-encoded envelope)
	Data string `json:"data"`
	// Algorithm is informational only; the algorithm recorded in the
	// envelope is what DecodeShare enforces.
	Algorithm string `json:"algorithm"`
	// ExpiresAt is honored only for legacy shares that predate
	// sharedContents. It is NOT authenticated: anyone holding the string can
	// edit it.
	ExpiresAt int64 `json:"expires_at,omitempty"`
}

// sharedContents is the plaintext encrypted inside a share. Putting the
// expiry here means it is covered by the envelope's integrity check and can't
// be stripped or extended by whoever relays the string.
type sharedContents struct {
	Version   int               `json:"v"`
	Vars      map[string]string `json:"vars"`
	ExpiresAt int64             `json:"expires_at,omitempty"`
}

const (
	sharedContentsVersion = 2
	// maxShareLen bounds the size of an evlt:// string DecodeShare will parse.
	maxShareLen = 4 << 20
)

// EncodeShare encrypts variables and returns an evlt:// encoded string
func EncodeShare(variables map[string]string, recipientPublicKey string, ttl uint) (string, error) {
	if len(variables) == 0 {
		return "", fmt.Errorf("no variables to share")
	}

	contents := sharedContents{Version: sharedContentsVersion, Vars: variables}
	if ttl > 0 {
		contents.ExpiresAt = time.Now().Add(time.Duration(ttl) * time.Second).Unix()
	}
	data, err := json.Marshal(contents)
	if err != nil {
		return "", fmt.Errorf("failed to serialize variables: %w", err)
	}
	defer SecureWipe(data)

	// Get Age provider for public key encryption
	provider := &AgePubKeyProvider{ID: "age-pubkey"}

	// Encrypt using the recipient's public key. A share is handed to third
	// parties, so don't embed the sender's git author name/email.
	encrypted, err := encrypt(data, []byte(recipientPublicKey), false, provider)
	if err != nil {
		return "", fmt.Errorf("failed to encrypt: %w", err)
	}

	payloadJSON, err := json.Marshal(SharedPayload{
		Data:      base64.StdEncoding.EncodeToString(encrypted),
		Algorithm: "age-pubkey",
	})
	if err != nil {
		return "", fmt.Errorf("failed to marshal payload: %w", err)
	}

	return SharePrefix + base64.StdEncoding.EncodeToString(payloadJSON), nil
}

// DecodeShare decrypts an evlt:// encoded string
func DecodeShare(sharedString string) (map[string]string, error) {
	if len(sharedString) > maxShareLen {
		return nil, fmt.Errorf("share is too large")
	}
	if !strings.HasPrefix(sharedString, SharePrefix) {
		return nil, fmt.Errorf("invalid share format: must start with %s", SharePrefix)
	}

	payloadJSON, err := base64.StdEncoding.DecodeString(sharedString[len(SharePrefix):])
	if err != nil {
		return nil, fmt.Errorf("failed to decode share: %w", err)
	}

	var payload SharedPayload
	if err := json.Unmarshal(payloadJSON, &payload); err != nil {
		return nil, fmt.Errorf("failed to unmarshal payload: %w", err)
	}

	encrypted, err := base64.StdEncoding.DecodeString(payload.Data)
	if err != nil {
		return nil, fmt.Errorf("failed to decode encrypted data: %w", err)
	}

	// Decrypt() routes to whatever provider the (attacker-controlled)
	// envelope names, and several providers accept an empty password. Without
	// this check anyone could forge a share with no knowledge of the
	// recipient's key by encrypting under, say, aes256gcm-pbkdf2 with "".
	alg, err := PeekAlgorithm(encrypted)
	if err != nil {
		return nil, fmt.Errorf("failed to read share: %w", err)
	}
	if alg != "age-pubkey" {
		return nil, fmt.Errorf("invalid share: expected algorithm age-pubkey, got %q", alg)
	}

	decrypted, err := Decrypt(encrypted, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %w", err)
	}
	defer SecureWipe(decrypted)

	var contents sharedContents
	if err := json.Unmarshal(decrypted, &contents); err == nil && contents.Version == sharedContentsVersion {
		if contents.ExpiresAt > 0 && time.Now().Unix() > contents.ExpiresAt {
			return nil, fmt.Errorf("the shared data has expired")
		}
		if contents.Vars == nil {
			contents.Vars = map[string]string{}
		}
		return contents.Vars, nil
	}

	// Legacy share: bare map of variables, expiry only in the outer wrapper.
	if payload.ExpiresAt > 0 && time.Now().Unix() > payload.ExpiresAt {
		return nil, fmt.Errorf("the shared data has expired")
	}
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
