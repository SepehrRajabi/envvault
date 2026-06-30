package cmd

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/SepehrRajabi/envvault/crypto"
	"github.com/SepehrRajabi/envvault/envfile"
	"github.com/SepehrRajabi/envvault/history"
	"github.com/spf13/cobra"
)

var (
	mutationRecipients []string
	envKeyPattern      = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
)

type loadedEnvDocument struct {
	Path      string
	IsVault   bool
	Algorithm string
	Data      []byte
	Password  []byte
	Provider  crypto.Provider
	Locked    *crypto.LockedBytes
}

func (d *loadedEnvDocument) Close() {
	if d.Locked != nil {
		d.Locked.Unlock()
	}
	if d.Password != nil {
		crypto.SecureWipe(d.Password)
	}
}

func (d *loadedEnvDocument) Plaintext() []byte {
	if d.Locked != nil {
		return d.Locked.Bytes()
	}
	return d.Data
}

func (d *loadedEnvDocument) Save(content []byte, recipients []string) error {
	if !d.IsVault {
		return atomicWrite(d.Path, content)
	}

	password := d.Password
	provider := d.Provider
	if d.Algorithm == "age-pubkey" {
		if len(recipients) == 0 {
			return fmt.Errorf("vault uses age-pubkey encryption; pass one or more --recipient/-r values to re-encrypt after modifying")
		}
		password = []byte(strings.Join(recipients, ","))
		var err error
		provider, err = crypto.GetProvider("age-pubkey")
		if err != nil {
			return err
		}
	}

	encrypted, err := crypto.Encrypt(content, password, provider)
	if err != nil {
		return fmt.Errorf("encrypting modified vault: %w", err)
	}
	if err := atomicWrite(d.Path, encrypted); err != nil {
		return fmt.Errorf("writing %s: %w", d.Path, err)
	}

	if shareProvider, ok := provider.(crypto.ShareExporter); ok {
		shares := shareProvider.GeneratedShares()
		if len(shares) > 0 {
			fmt.Fprintln(os.Stderr, "Shamir shares for the updated vault (store separately):")
			for i, share := range shares {
				fmt.Fprintf(os.Stderr, "  share %d: %s\n", i+1, share)
			}
		}
	}

	return nil
}

func loadEnvDocument(filePath string) (*loadedEnvDocument, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", filePath, err)
	}

	doc := &loadedEnvDocument{Path: filePath, Data: data}
	if !isVaultFile(filePath, data) {
		return doc, nil
	}

	doc.IsVault = true
	alg, err := crypto.PeekAlgorithm(data)
	if err != nil {
		return nil, fmt.Errorf("reading vault metadata: %w", err)
	}
	doc.Algorithm = alg

	password, err := getVaultCredentials(data, filePath)
	if err != nil {
		return nil, err
	}
	doc.Password = password

	provider, err := crypto.GetProvider(alg)
	if err != nil {
		doc.Close()
		return nil, fmt.Errorf("unknown algorithm %q: %w", alg, err)
	}
	doc.Provider = provider

	lockedPlaintext, err := crypto.DecryptSecure(data, password, provider)
	if err != nil {
		doc.Close()
		return nil, fmt.Errorf("decrypting failed for %s: %w", filePath, err)
	}
	doc.Locked = lockedPlaintext

	return doc, nil
}

type envLine struct {
	Raw   string
	Key   string
	Value string
	IsKV  bool
}

func parseEnvDocumentLines(content string) ([]envLine, error) {
	parts := strings.Split(content, "\n")
	if len(parts) > 0 && parts[len(parts)-1] == "" {
		parts = parts[:len(parts)-1]
	}

	lines := make([]envLine, 0, len(parts))
	for i, line := range parts {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			lines = append(lines, envLine{Raw: line})
			continue
		}

		before, after, found := strings.Cut(line, "=")
		if !found {
			return nil, fmt.Errorf("invalid env format on line %d", i+1)
		}
		key := strings.TrimSpace(before)
		if key == "" {
			return nil, fmt.Errorf("invalid empty key on line %d", i+1)
		}
		lines = append(lines, envLine{
			Raw:   line,
			Key:   key,
			Value: strings.TrimSpace(after),
			IsKV:  true,
		})
	}

	return lines, nil
}

func formatEnvDocumentLines(lines []envLine) []byte {
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		out = append(out, line.Raw)
	}
	return []byte(strings.Join(out, "\n") + "\n")
}

func validateEnvKey(key string) error {
	if !envKeyPattern.MatchString(key) {
		return fmt.Errorf("invalid env key %q: keys must match %s", key, envKeyPattern.String())
	}
	return nil
}

func getEnvValue(content []byte, key string) (string, bool, error) {
	if err := validateEnvKey(key); err != nil {
		return "", false, err
	}
	vars, err := envfile.Parse(string(content))
	if err != nil {
		return "", false, err
	}
	for _, envVar := range vars {
		if envVar.Key == key {
			return envVar.Value, true, nil
		}
	}
	return "", false, nil
}

func setEnvValue(content []byte, key, value string) ([]byte, bool, error) {
	if err := validateEnvKey(key); err != nil {
		return nil, false, err
	}
	lines, err := parseEnvDocumentLines(string(content))
	if err != nil {
		return nil, false, err
	}

	updated := false
	for i := range lines {
		if lines[i].IsKV && lines[i].Key == key {
			lines[i].Value = value
			lines[i].Raw = fmt.Sprintf("%s=%s", key, value)
			updated = true
			break
		}
	}
	if !updated {
		lines = append(lines, envLine{Raw: fmt.Sprintf("%s=%s", key, value), Key: key, Value: value, IsKV: true})
	}

	return formatEnvDocumentLines(lines), updated, nil
}

func unsetEnvValue(content []byte, key string) ([]byte, bool, error) {
	if err := validateEnvKey(key); err != nil {
		return nil, false, err
	}
	lines, err := parseEnvDocumentLines(string(content))
	if err != nil {
		return nil, false, err
	}

	removed := false
	filtered := lines[:0]
	for _, line := range lines {
		if line.IsKV && line.Key == key {
			removed = true
			continue
		}
		filtered = append(filtered, line)
	}

	return formatEnvDocumentLines(filtered), removed, nil
}

func renameEnvKey(content []byte, oldKey, newKey string) ([]byte, error) {
	if err := validateEnvKey(oldKey); err != nil {
		return nil, err
	}
	if err := validateEnvKey(newKey); err != nil {
		return nil, err
	}
	if oldKey == newKey {
		return nil, fmt.Errorf("old and new key are the same: %s", oldKey)
	}

	lines, err := parseEnvDocumentLines(string(content))
	if err != nil {
		return nil, err
	}

	oldIndex := -1
	for i, line := range lines {
		if !line.IsKV {
			continue
		}
		if line.Key == newKey {
			return nil, fmt.Errorf("target key already exists: %s", newKey)
		}
		if line.Key == oldKey {
			oldIndex = i
		}
	}
	if oldIndex == -1 {
		return nil, fmt.Errorf("key not found: %s", oldKey)
	}

	lines[oldIndex].Key = newKey
	lines[oldIndex].Raw = fmt.Sprintf("%s=%s", newKey, lines[oldIndex].Value)
	return formatEnvDocumentLines(lines), nil
}

var getCmd = &cobra.Command{
	Use:   "get [envfile / vaultfile] [key]",
	Short: "Get a single environment variable value",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		doc, err := loadEnvDocument(args[0])
		if err != nil {
			return err
		}
		defer doc.Close()

		value, found, err := getEnvValue(doc.Plaintext(), args[1])
		if err != nil {
			return err
		}
		if !found {
			return fmt.Errorf("key not found: %s", args[1])
		}
		fmt.Println(value)
		return nil
	},
}

var setCmd = &cobra.Command{
	Use:   "set [envfile / vaultfile] [key] [value]",
	Short: "Set an environment variable value",
	Args:  cobra.ExactArgs(3),
	RunE: func(cmd *cobra.Command, args []string) error {
		doc, err := loadEnvDocument(args[0])
		if err != nil {
			return err
		}
		defer doc.Close()

		updatedContent, existed, err := setEnvValue(doc.Plaintext(), args[1], args[2])
		if err != nil {
			return err
		}
		if err := doc.Save(updatedContent, mutationRecipients); err != nil {
			return err
		}

		action := "Set"
		if !existed {
			action = "Added"
		}
		fmt.Printf("%s %s in %s\n", action, args[1], args[0])
		_ = history.Record("Set", args[0], doc.Algorithm)
		return nil
	},
}

var unsetCmd = &cobra.Command{
	Use:     "unset [envfile / vaultfile] [key]",
	Aliases: []string{"remove"},
	Short:   "Remove an environment variable",
	Args:    cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		doc, err := loadEnvDocument(args[0])
		if err != nil {
			return err
		}
		defer doc.Close()

		updatedContent, removed, err := unsetEnvValue(doc.Plaintext(), args[1])
		if err != nil {
			return err
		}
		if !removed {
			return fmt.Errorf("key not found: %s", args[1])
		}
		if err := doc.Save(updatedContent, mutationRecipients); err != nil {
			return err
		}

		fmt.Printf("Removed %s from %s\n", args[1], args[0])
		_ = history.Record("Unset", args[0], doc.Algorithm)
		return nil
	},
}

var renameCmd = &cobra.Command{
	Use:   "rename [envfile / vaultfile] [old-key] [new-key]",
	Short: "Rename an environment variable key",
	Args:  cobra.ExactArgs(3),
	RunE: func(cmd *cobra.Command, args []string) error {
		doc, err := loadEnvDocument(args[0])
		if err != nil {
			return err
		}
		defer doc.Close()

		updatedContent, err := renameEnvKey(doc.Plaintext(), args[1], args[2])
		if err != nil {
			return err
		}
		if err := doc.Save(updatedContent, mutationRecipients); err != nil {
			return err
		}

		fmt.Printf("Renamed %s to %s in %s\n", args[1], args[2], args[0])
		_ = history.Record("Rename", args[0], doc.Algorithm)
		return nil
	},
}

func init() {
	setCmd.Flags().StringArrayVarP(&mutationRecipients, "recipient", "r", nil, "Age public key(s) for re-encrypting age-pubkey vaults (can be specified multiple times)")
	unsetCmd.Flags().StringArrayVarP(&mutationRecipients, "recipient", "r", nil, "Age public key(s) for re-encrypting age-pubkey vaults (can be specified multiple times)")
	renameCmd.Flags().StringArrayVarP(&mutationRecipients, "recipient", "r", nil, "Age public key(s) for re-encrypting age-pubkey vaults (can be specified multiple times)")

	rootCmd.AddCommand(getCmd)
	rootCmd.AddCommand(setCmd)
	rootCmd.AddCommand(unsetCmd)
	rootCmd.AddCommand(renameCmd)
}
