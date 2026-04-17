package cmd

import (
	"os"
	"path/filepath"

	"github.com/SepehrRajabi/envvault/crypto"
)

// atomicWrite writes data by first writing to a temp file in the same directory,
// then renaming it. This prevents corruption if the program is interrupted.
func atomicWrite(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmpFile, err := os.CreateTemp(dir, ".envvault-write-*")
	if err != nil {
		return err
	}
	tmpPath := tmpFile.Name()

	// On any failure, clean up the temp file
	defer func() {
		if _, err := os.Stat(tmpPath); err == nil {
			os.Remove(tmpPath)
		}
	}()

	if _, err := tmpFile.Write(data); err != nil {
		tmpFile.Close()
		return err
	}
	if err := tmpFile.Sync(); err != nil {
		tmpFile.Close()
		return err
	}
	if err := tmpFile.Close(); err != nil {
		return err
	}
	// Atomically replace the original file
	return os.Rename(tmpPath, path)
}

// getVaultCredentials determines if a vault requires a password or a private key
// and returns the appropriate credential (or empty byte slice for pubkey vaults).
func getVaultCredentials(data []byte) ([]byte, error) {
	alg, _ := crypto.PeekAlgorithm(data)

	if alg == "age-pubkey" {
		// No password needed, the provider will look for the private key automatically
		return []byte(""), nil
	}

	// Standard password-encrypted vault
	return crypto.GetPassword("Enter password: ")
}
