package crypto

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"filippo.io/age"
)

type AgePubKeyProvider struct{}

func (a *AgePubKeyProvider) AlgorithmID() string {
	return "age-pubkey"
}

func (a *AgePubKeyProvider) Encrypt(plaintext, publicKeyBytes []byte) ([]byte, error) {
	publicKeyStr := strings.TrimSpace(string(publicKeyBytes))
	if publicKeyStr == "" {
		return nil, fmt.Errorf("no public key provided. Use --recipient flag")
	}

	// Split by comma to support multiple recipients
	keyStrings := strings.Split(publicKeyStr, ",")
	var recipients []age.Recipient

	for _, keyStr := range keyStrings {
		keyStr = strings.TrimSpace(keyStr)
		if keyStr == "" {
			continue
		}

		recipient, err := age.ParseX25519Recipient(keyStr)
		if err != nil {
			return nil, fmt.Errorf("invalid age public key %q: %w", keyStr, err)
		}
		recipients = append(recipients, recipient)
	}

	if len(recipients) == 0 {
		return nil, fmt.Errorf("no valid public keys provided")
	}

	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, recipients...)
	if err != nil {
		return nil, fmt.Errorf("initializing age encryption: %w", err)
	}

	if _, err := w.Write(plaintext); err != nil {
		return nil, fmt.Errorf("writing plaintext: %w", err)
	}

	if err := w.Close(); err != nil {
		return nil, fmt.Errorf("closing age encryption: %w", err)
	}

	return buf.Bytes(), nil
}

// Decrypt ignores the 'password' parameter and instead looks for the private key
// in the AGE_IDENTITY environment variable or ~/.config/age/keys.txt
func (a *AgePubKeyProvider) Decrypt(payload, _ []byte) ([]byte, error) {
	identities, err := a.loadIdentities()
	if err != nil {
		return nil, fmt.Errorf("loading age identities: %w", err)
	}

	r, err := age.Decrypt(bytes.NewReader(payload), identities...)
	if err != nil {
		return nil, fmt.Errorf("decryption failed (no matching private key?): %w", err)
	}

	var buf bytes.Buffer
	if _, err := buf.ReadFrom(r); err != nil {
		return nil, fmt.Errorf("reading decrypted data: %w", err)
	}

	return buf.Bytes(), nil
}

// loadIdentities mimics the standard age CLI behavior
func (a *AgePubKeyProvider) loadIdentities() ([]age.Identity, error) {
	if envKey := os.Getenv("AGE_IDENTITY"); envKey != "" {
		id, err := age.ParseX25519Identity(strings.TrimSpace(envKey))
		if err != nil {
			return nil, fmt.Errorf("parsing AGE_IDENTITY env var: %w", err)
		}
		return []age.Identity{id}, nil
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("finding home directory: %w", err)
	}

	envvaultPath := filepath.Join(home, ".envvault", "keys.txt")
	if identities, err := parseKeyFile(envvaultPath); err == nil && len(identities) > 0 {
		return identities, nil
	}

	agePath := filepath.Join(home, ".config", "age", "keys.txt")
	if identities, err := parseKeyFile(agePath); err == nil && len(identities) > 0 {
		return identities, nil
	}

	return nil, fmt.Errorf("no private key found. Set AGE_IDENTITY env var or create ~/.envvault/keys.txt")
}

func (a *AgePubKeyProvider) Description() ProviderInfo {
	return ProviderInfo{
		ID:          a.AlgorithmID(),
		Description: "Encrypt with recipient's public key. Decrypt with your private key in AGE_IDENTITY or ~/.config/age/keys.txt",
		Secure:      true,
	}
}

// parseKeyFile attempts to parse an age key file
func parseKeyFile(path string) ([]age.Identity, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	return age.ParseIdentities(f)
}

func init() {
	Register(&AgePubKeyProvider{})
}
