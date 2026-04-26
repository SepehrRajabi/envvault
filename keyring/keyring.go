package keyring

import (
	"fmt"

	kr "github.com/zalando/go-keyring"
)

const (
	// ServiceName is the keyring service identifier for envvault
	ServiceName = "envvault"
	// KeyringKey is the key used to store the decryption key in the keyring
	KeyringKey = "decryption_key"
)

// StoreKey stores the decryption key in the OS keystore
func StoreKey(key string) error {
	if key == "" {
		return fmt.Errorf("key cannot be empty")
	}

	err := kr.Set(ServiceName, KeyringKey, key)
	if err != nil {
		return fmt.Errorf("failed to store key in keyring: %w", err)
	}

	return nil
}

// RetrieveKey retrieves the decryption key from the OS keystore
func RetrieveKey() (string, error) {
	key, err := kr.Get(ServiceName, KeyringKey)
	if err != nil {
		return "", fmt.Errorf("failed to retrieve key from keyring: %w", err)
	}

	return key, nil
}

// DeleteKey removes the decryption key from the OS keystore
func DeleteKey() error {
	err := kr.Delete(ServiceName, KeyringKey)
	if err != nil {
		return fmt.Errorf("failed to delete key from keyring: %w", err)
	}

	return nil
}

// HasKey checks if a key is stored in the OS keystore
func HasKey() bool {
	_, err := RetrieveKey()
	return err == nil
}
