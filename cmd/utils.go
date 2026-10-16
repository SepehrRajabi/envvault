package cmd

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unicode"

	"github.com/SepehrRajabi/envvault/crypto"
	"github.com/SepehrRajabi/envvault/homedir"
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

// writeSecretFile writes sensitive plaintext (decrypted .env files, generated
// manifests) to path with mode 0600. It writes a fresh 0600 temp file and
// renames it into place, so an existing file's looser permissions are never
// inherited. It refuses to write through a symlink (which could redirect the
// secrets to an attacker-chosen location) or over a non-regular file.
func writeSecretFile(path string, data []byte) error {
	if info, err := os.Lstat(path); err == nil {
		switch {
		case info.Mode()&os.ModeSymlink != 0:
			return fmt.Errorf("refusing to write secrets to %s: it is a symbolic link", path)
		case !info.Mode().IsRegular():
			return fmt.Errorf("refusing to write secrets to %s: not a regular file", path)
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	return atomicWrite(path, data)
}

type quorumState struct {
	VaultPath   string   `json:"vault_path,omitempty"`
	PayloadHash string   `json:"payload_hash,omitempty"`
	Threshold   int      `json:"threshold"`
	Shares      []string `json:"shares,omitempty"`
}

func quorumStatePath(filePath string) (string, error) {
	absPath, err := filepath.Abs(filePath)
	if err != nil {
		return "", err
	}
	home, err := homedir.Dir()
	if err != nil {
		return "", fmt.Errorf("finding home directory: %w", err)
	}
	// Submitted shares are secrets, so keep the state in the user's private
	// envvault directory rather than next to the vault, where it could be
	// committed or read by anyone with access to the repo checkout.
	hash := sha256.Sum256([]byte(absPath))
	return filepath.Join(home, ".envvault", "quorum", fmt.Sprintf("%x.json", hash[:16])), nil
}

func loadQuorumState(path string) (*quorumState, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var state quorumState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, err
	}
	return &state, nil
}

func saveQuorumState(path string, state *quorumState) error {
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	return atomicWrite(path, data)
}

func clearQuorumState(path string) error {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil
	}
	return os.Remove(path)
}

func sha256Sum(data []byte) string {
	sum := sha256.Sum256(data)
	return fmt.Sprintf("%x", sum[:])
}

func isValidBase64(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" {
		return false
	}
	_, err := base64.StdEncoding.DecodeString(value)
	return err == nil
}

// trustRequired reports whether a missing trust pin must be a hard failure,
// via --require-trust or a truthy ENVVAULT_REQUIRE_TRUST (1/true/yes/on).
func trustRequired() bool {
	if requireTrust {
		return true
	}
	switch strings.ToLower(strings.TrimSpace(os.Getenv("ENVVAULT_REQUIRE_TRUST"))) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

// enforceTrust verifies that a vault's actual algorithm/recipients match
// whatever was pinned for its path (via `envvault lock` or `envvault trust`).
// It must be called before any credential prompt or decryption attempt:
// otherwise an attacker who overwrites a vault file with content encrypted
// under a different algorithm or recipient set (but still decryptable by the
// victim's own key) would be silently accepted. A vault with no pin yet is
// allowed through with a warning, so first-time use isn't broken.
func enforceTrust(filePath string, data []byte) error {
	hdr, err := crypto.Verify(data)
	if err != nil {
		return fmt.Errorf("verifying %s: %w", filePath, err)
	}

	if err := crypto.CheckTrust(filePath, data, hdr); err != nil {
		if err == crypto.ErrUntrustedVault {
			if trustRequired() {
				return fmt.Errorf(
					"vault %s has no trust pin and trust is required (--require-trust / ENVVAULT_REQUIRE_TRUST) — "+
						"pin it first with `envvault trust %s` after verifying it out-of-band, or pre-register "+
						"expected values with `envvault trust %s --algorithm ... [--recipient ...]`",
					filePath, filePath, filePath)
			}
			fmt.Fprintf(os.Stderr,
				"⚠️  No trust record for %s — run `envvault trust %s` after verifying its contents to pin it and detect future substitution.\n",
				filePath, filePath)
			return nil
		}
		return err
	}

	return nil
}

// rejectPlaintextDowngrade fails if path has a trust pin yet its content isn't
// a vault. isVaultFile treats anything without the .vault suffix or an
// envelope version byte as a plain .env, so without this a pinned vault
// replaced by plaintext (under a name without the .vault suffix) would skip
// every trust check and be read as-is.
func rejectPlaintextDowngrade(path string) error {
	if _, pinned, err := crypto.GetTrust(path); err == nil && pinned {
		return fmt.Errorf("%s is pinned as a vault (see `envvault trust --show`) but contains plaintext — "+
			"it may have been replaced; run `envvault trust %s --clear` if this is expected", path, path)
	}
	return nil
}

// sanitizeForTerminal replaces control characters (ESC, CR, BEL, C1 codes...)
// in strings that came from an untrusted file (vault headers, file names)
// before they're printed, so a crafted vault can't inject terminal escape
// sequences or overwrite what the user is reading.
func sanitizeForTerminal(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return '?'
		}
		return r
	}, s)
}

// refreshTrustPin re-pins a vault after a legitimate in-place re-encryption,
// so the next read doesn't mistake it for a substitution. Failure is only a
// warning, matching lock/edit/rotate.
func refreshTrustPin(filePath string, encrypted []byte) {
	hdr, err := crypto.Verify(encrypted)
	if err == nil {
		err = crypto.SetTrust(filePath, crypto.TrustRecord{
			Algorithm:  hdr.Algorithm,
			Recipients: crypto.RecipientsFromHeader(hdr),
			Checksum:   crypto.HashVaultChecksum(encrypted),
		})
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "⚠️  Warning: failed to update trust pin for %s: %v\n", filePath, err)
	}
}

// reencryptionPlan returns the provider and secret to use when re-encrypting
// a modified vault *under its existing algorithm* (edit, set/unset/rename).
// Re-encrypting with the default provider would silently change a vault's
// algorithm. The secret is the vault password, except for Shamir vaults where
// it's the reconstructed shared secret, so the shares holders already have
// keep working. Not for age-pubkey vaults, which callers handle through
// recipients. The caller must wipe the returned secret if it differs from
// password.
func reencryptionPlan(data, password []byte) (crypto.Provider, []byte, error) {
	alg, err := crypto.PeekAlgorithm(data)
	if err != nil {
		return nil, nil, err
	}
	switch alg {
	case "age-pubkey":
		return nil, nil, fmt.Errorf("age-pubkey vaults are re-encrypted through their recipients")
	case "shamir-aes256gcm":
		threshold, err := crypto.DecodeShamirPayloadThreshold(data)
		if err != nil {
			return nil, nil, err
		}
		secret, err := crypto.ShamirSecretFromShares(password, threshold)
		if err != nil {
			return nil, nil, fmt.Errorf("reconstructing shamir secret: %w", err)
		}
		return crypto.NewShamirProvider(max(5, threshold), threshold), secret, nil
	}
	p, err := crypto.GetProvider(alg)
	if err != nil {
		return nil, nil, err
	}
	return p, password, nil
}

// requireSecureAlgorithm refuses insecure providers unless allowInsecure.
func requireSecureAlgorithm(p crypto.Provider, allowInsecure bool) error {
	if !allowInsecure && !p.Description().Secure {
		return fmt.Errorf("selected algorithm, %s, is not secure (use --allow-insecure to override)", p.AlgorithmID())
	}
	return nil
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
	if len(data) > 0 && (data[0] == 1 || data[0] == 2) {
		return true
	}
	return false
}

func getVaultInfo(filePath string) (*VaultInfo, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	hdr, err := crypto.Verify(data)
	if err != nil {
		return nil, err
	}

	hasKeyring := false
	storedKey, err := keyring.RetrieveKey(filePath)
	if err == nil && storedKey != "" {
		hasKeyring = true
	}

	return &VaultInfo{
		Algorithm:  hdr.Algorithm,
		HasKeyring: hasKeyring,
		Version:    hdr.Version,
	}, nil
}
