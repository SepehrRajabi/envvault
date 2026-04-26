package keyring

// GetDecryptionKey attempts to get the decryption key in this order:
// 1. From the --key flag (if provided)
// 2. From the OS keyring for the specific file/project (if stored via 'envvault login [file]')
// 3. From the default OS keyring (if stored via 'envvault login')
// 4. Returns empty string if none found
func GetDecryptionKey(keyFlag string, filePath string) string {
	// If key flag is provided, use it
	if keyFlag != "" {
		return keyFlag
	}

	// Try to retrieve from OS keyring (file-specific or default)
	key, err := RetrieveKey(filePath)
	if err == nil {
		return key
	}

	return ""
}
