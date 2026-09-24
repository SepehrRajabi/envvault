package crypto

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"

	"github.com/SepehrRajabi/envvault/homedir"
)

// TrustRecord pins the metadata a vault file is expected to carry: the
// algorithm it was locked with and, for public-key algorithms, the set of
// recipients it was encrypted for. It is recorded locally (outside the
// vault's own directory) when a vault is first locked or explicitly trusted,
// and checked again on every subsequent unlock/export/run so that swapping
// the vault file on disk for one encrypted under a different algorithm or
// recipient set is detected instead of silently accepted.
type TrustRecord struct {
	Algorithm  string   `json:"algorithm"`
	Recipients []string `json:"recipients,omitempty"`
}

type trustStore struct {
	Vaults map[string]TrustRecord `json:"vaults"`
}

// TrustStorePath returns the location of the local trust database.
func TrustStorePath() (string, error) {
	home, err := homedir.Dir()
	if err != nil {
		return "", fmt.Errorf("finding home directory: %w", err)
	}
	return filepath.Join(home, ".envvault", "trust.json"), nil
}

func loadTrustStore() (*trustStore, error) {
	path, err := TrustStorePath()
	if err != nil {
		return nil, err
	}

	store := &trustStore{Vaults: make(map[string]TrustRecord)}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return store, nil
		}
		return nil, fmt.Errorf("reading trust store %s: %w", path, err)
	}

	if len(data) == 0 {
		return store, nil
	}

	if err := json.Unmarshal(data, store); err != nil {
		return nil, fmt.Errorf("parsing trust store %s: %w", path, err)
	}
	if store.Vaults == nil {
		store.Vaults = make(map[string]TrustRecord)
	}

	return store, nil
}

func (s *trustStore) save() error {
	path, err := TrustStorePath()
	if err != nil {
		return err
	}

	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return fmt.Errorf("creating trust store directory: %w", err)
	}

	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding trust store: %w", err)
	}

	return os.WriteFile(path, data, 0600)
}

func trustKey(filePath string) (string, error) {
	abs, err := filepath.Abs(filePath)
	if err != nil {
		return "", fmt.Errorf("resolving %s: %w", filePath, err)
	}
	return abs, nil
}

// RecipientsFromHeader extracts the recipient public keys recorded in a
// vault's envelope header, if any (only present for public-key algorithms).
func RecipientsFromHeader(hdr *envelopeHeader) []string {
	if hdr == nil || hdr.ProviderParams == nil {
		return nil
	}

	raw, ok := hdr.ProviderParams["recipients"]
	if !ok {
		return nil
	}

	var recipients []string
	switch v := raw.(type) {
	case []string:
		recipients = append(recipients, v...)
	case []any:
		for _, item := range v {
			if s, ok := item.(string); ok && s != "" {
				recipients = append(recipients, s)
			}
		}
	}

	sort.Strings(recipients)
	return recipients
}

// SetTrust pins the expected algorithm/recipients for a vault path,
// overwriting any existing record.
func SetTrust(filePath string, record TrustRecord) error {
	key, err := trustKey(filePath)
	if err != nil {
		return err
	}

	store, err := loadTrustStore()
	if err != nil {
		return err
	}

	sort.Strings(record.Recipients)
	store.Vaults[key] = record

	return store.save()
}

// GetTrust returns the pinned record for a vault path, if one exists.
func GetTrust(filePath string) (TrustRecord, bool, error) {
	key, err := trustKey(filePath)
	if err != nil {
		return TrustRecord{}, false, err
	}

	store, err := loadTrustStore()
	if err != nil {
		return TrustRecord{}, false, err
	}

	record, ok := store.Vaults[key]
	return record, ok, nil
}

// ClearTrust removes any pinned record for a vault path.
func ClearTrust(filePath string) error {
	key, err := trustKey(filePath)
	if err != nil {
		return err
	}

	store, err := loadTrustStore()
	if err != nil {
		return err
	}

	delete(store.Vaults, key)
	return store.save()
}

// ErrUntrustedVault is returned by CheckTrust when no pinned record exists
// for a vault path yet. Callers should treat this as a warning, not a hard
// failure, so first-time use of a vault still works.
var ErrUntrustedVault = fmt.Errorf("no trust record for this vault path")

// CheckTrust verifies that a vault's actual algorithm and recipients (as
// read from its envelope header) match what was previously pinned for its
// path via SetTrust. This is the core defense against vault substitution:
// an attacker who overwrites a vault file with content encrypted under a
// different algorithm or recipient set (even one that decrypts cleanly
// under the victim's own key) is caught here, before any credential prompt
// or decryption is attempted.
func CheckTrust(filePath string, hdr *envelopeHeader) error {
	record, ok, err := GetTrust(filePath)
	if err != nil {
		return err
	}
	if !ok {
		return ErrUntrustedVault
	}

	if hdr.Algorithm != record.Algorithm {
		return fmt.Errorf(
			"vault %s was pinned with algorithm %q but now has algorithm %q — "+
				"the file may have been substituted; run `envvault trust %s --clear` if this change is expected",
			filePath, record.Algorithm, hdr.Algorithm, filePath,
		)
	}

	actual := RecipientsFromHeader(hdr)
	if len(record.Recipients) > 0 && !slices.Equal(record.Recipients, actual) {
		return fmt.Errorf(
			"vault %s was pinned for recipients %v but now has recipients %v — "+
				"the file may have been substituted; run `envvault trust %s --clear` if this change is expected",
			filePath, record.Recipients, actual, filePath,
		)
	}

	return nil
}
