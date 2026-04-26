package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/SepehrRajabi/envvault/crypto"
	"github.com/SepehrRajabi/envvault/keyring"
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
// It first checks the OS keyring for a stored key for this file before prompting the user.
// filePath is used to look up project-specific keys in the keyring.
func getVaultCredentials(data []byte, filePath string) ([]byte, error) {
	alg, _ := crypto.PeekAlgorithm(data)

	if alg == "age-pubkey" {
		// No password needed, the provider will look for the private key automatically
		return []byte(""), nil
	}

	// Try to get key from OS keyring first (file-specific or default)
	storedKey, err := keyring.RetrieveKey(filePath)
	if err == nil && storedKey != "" {
		return []byte(storedKey), nil
	}

	if alg == "shamir-aes256gcm" {
		threshold, err := crypto.DecodeShamirPayloadThreshold(data)
		if err != nil {
			return nil, err
		}
		return crypto.GetPassword(fmt.Sprintf(
			"Enter Shamir shares (base64, comma-separated; need at least %d): ",
			threshold,
		))
	}

	// Standard password-encrypted vault
	return crypto.GetPassword("Enter password: ")
}

func writeSharesToFiles(dir, prefix string, shares []string) ([]string, error) {
	if dir == "" {
		return nil, fmt.Errorf("shares output directory is empty")
	}
	if len(shares) == 0 {
		return nil, nil
	}

	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("creating shares output directory: %w", err)
	}

	paths := make([]string, 0, len(shares))
	for i, share := range shares {
		path := filepath.Join(dir, fmt.Sprintf("%s-%d.txt", prefix, i+1))
		if err := os.WriteFile(path, []byte(share+"\n"), 0600); err != nil {
			return nil, fmt.Errorf("writing share file %s: %w", path, err)
		}
		paths = append(paths, path)
	}

	return paths, nil
}

func isVaultFile(path string, data []byte) bool {
	// Fast check: file extension
	if strings.HasSuffix(path, ".vault") {
		return true
	}
	// Fallback: check the envelope version byte
	if len(data) > 0 && data[0] == 1 {
		return true
	}
	return false
}
