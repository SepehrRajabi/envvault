// Package keyring stores and retrieves secrets — vault decryption keys, and
// other entries like the history HTTP backend's auth token — in the OS
// keychain via zalando/go-keyring.
package keyring

import (
	"fmt"

	kr "github.com/zalando/go-keyring"
)

const (
	// ServiceName is the keyring service identifier for envvault
	ServiceName = "envvault"
	// DefaultKeyringKey is the default key used when no file path is specified
	DefaultKeyringKey = "default-decryption-key"
)

// StoreKey stores the decryption key in the OS keystore.
// If filePath is empty, stores as default key. Otherwise, uses filePath as the key.
func StoreKey(key string, filePath string) error {
	if key == "" {
		return fmt.Errorf("key cannot be empty")
	}

	keyName := DefaultKeyringKey
	if filePath != "" {
		keyName = filePath
	}

	err := kr.Set(ServiceName, keyName, key)
	if err != nil {
		return fmt.Errorf("failed to store key in keyring: %w", err)
	}

	return nil
}

// RetrieveKey retrieves the decryption key from the OS keystore.
// If filePath is provided, tries to get the project-specific key first, then falls back to default.
// If filePath is empty, retrieves the default key.
func RetrieveKey(filePath string) (string, error) {
	keyNames := []string{}

	// Priority order:
	// 1. If filePath provided, try project-specific key first
	if filePath != "" {
		keyNames = append(keyNames, filePath)
	}
	// 2. Always try default key as fallback
	keyNames = append(keyNames, DefaultKeyringKey)

	var lastErr error
	for _, keyName := range keyNames {
		key, err := kr.Get(ServiceName, keyName)
		if err == nil {
			return key, nil
		}
		lastErr = err
	}

	if lastErr == kr.ErrNotFound {
		return "", fmt.Errorf("key not found in keychain. Run 'envvault login [vault-file]' first")
	}
	// Catch the Linux DBus/Secret Service error specifically if possible
	return "", fmt.Errorf("keychain unavailable (are you on a headless Linux server?): %w", lastErr)
}

// RetrieveExact retrieves a value stored under an exact keyring key, with no
// fallback to DefaultKeyringKey. Use this for keyring entries that aren't
// vault decryption keys (e.g. a remote history backend's auth token) —
// RetrieveKey's fallback would otherwise silently return the user's default
// vault key when the specific entry isn't set.
func RetrieveExact(key string) (string, error) {
	value, err := kr.Get(ServiceName, key)
	if err != nil {
		if err == kr.ErrNotFound {
			return "", fmt.Errorf("key not found in keychain")
		}
		return "", fmt.Errorf("keychain unavailable (are you on a headless Linux server?): %w", err)
	}
	return value, nil
}

// HasExactKey checks whether a value is stored under an exact keyring key,
// with no fallback to DefaultKeyringKey. See RetrieveExact.
func HasExactKey(key string) bool {
	_, err := RetrieveExact(key)
	return err == nil
}

// DeleteKey removes the decryption key from the OS keystore.
// If filePath is empty, deletes the default key. Otherwise, deletes the project-specific key.
func DeleteKey(filePath string) error {
	keyName := DefaultKeyringKey
	if filePath != "" {
		keyName = filePath
	}

	err := kr.Delete(ServiceName, keyName)
	if err != nil {
		return fmt.Errorf("failed to delete key from keyring: %w", err)
	}

	return nil
}

// HasKey checks if a key is stored in the OS keystore.
// If filePath is provided, checks both project-specific and default keys.
// If filePath is empty, checks only the default key.
func HasKey(filePath string) bool {
	_, err := RetrieveKey(filePath)
	return err == nil
}
