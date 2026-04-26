package keyring

// GetDecryptionKey attempts to get the decryption key in this order:
// 1. From the --key flag (if provided)
// 2. From the OS keyring (if stored via 'envvault login')
// 3. Returns empty string if none found
func GetDecryptionKey(keyFlag string) string {
	// If key flag is provided, use it
	if keyFlag != "" {
		return keyFlag
	}

	// Try to retrieve from OS keyring
	key, err := RetrieveKey()
	if err == nil {
		return key
	}

	return ""
}
