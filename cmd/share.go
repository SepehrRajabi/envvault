package cmd

import (
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/SepehrRajabi/envvault/crypto"
	"github.com/SepehrRajabi/envvault/envfile"
	"github.com/spf13/cobra"
)

var (
	shareWith     string
	shareVarsFile string
)

var shareCmd = &cobra.Command{
	Use:   "share [env-file / vault-file] [VAR1] [VAR2] ... --with <recipient-pubkey>",
	Short: "Share specific variables with a recipient using their Age public key",
	Long: `Extract and encrypt specific environment variables for a recipient.

Supports multiple ways to specify variables:
- Direct arguments: envvault share VAR1 VAR2 VAR3 --with age1...
- Wildcard patterns: envvault share "DB_*" API_* --with age1...
- From file: envvault share --vars-file vars.txt --with age1...

The output is a base64 string prefixed with 'evlt://' that can be shared via any channel.
The recipient can decrypt it with: envvault receive <base64_string>`,
	Args: cobra.ArbitraryArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		if shareWith == "" {
			return fmt.Errorf("--with flag is required (recipient's Age public key)")
		}

		filePath := args[0]

		var filters []string

		// Get filters from arguments
		filters = append(filters, args...)

		// Get filters from file if provided
		if shareVarsFile != "" {
			fileFilters, err := readFiltersFromFile(shareVarsFile)
			if err != nil {
				return err
			}
			filters = append(filters, fileFilters...)
		}

		if len(filters) == 0 {
			return fmt.Errorf("must specify variables to share (as arguments or via --vars-file)")
		}

		loadVars := func(filePath string) ([]envfile.EnvVar, error) {
			data, err := os.ReadFile(filePath)
			if err != nil {
				return nil, fmt.Errorf("reading %s: %w", filePath, err)
			}

			hdr, err := crypto.Verify(data)
			if err != nil {
				return nil, fmt.Errorf("verifying %s: %w", filePath, err)
			}

			recipientKeys := hdr.ProviderParams["recipients"].([]map[string]any)
			if !slices.ContainsFunc(recipientKeys, func(key map[string]any) bool {
				return key["recipient"] == shareWith
			}) {
				return nil, fmt.Errorf("the file %s is not encrypted for the recipient %s", filePath, shortenPublicKey(shareWith))
			}

			// Detect if it's a vault file
			if isVaultFile(filePath, data) {
				password, err := getVaultCredentials(data, filePath)
				if err != nil {
					return nil, err
				}
				defer crypto.SecureWipe(password)

				// Try to decrypt
				var p crypto.Provider
				if algorithm != "" {
					var err error
					p, err = crypto.GetProvider(algorithm)
					if err != nil {
						return nil, fmt.Errorf("unknown algorithm %q: %w", algorithm, err)
					}
				}
				lockedPlaintext, err := crypto.DecryptSecure(data, password, p)
				if err != nil {
					return nil, fmt.Errorf("decrypting failed for %s: %w", filePath, err)
				}
				defer lockedPlaintext.Unlock()

				return envfile.Parse(string(lockedPlaintext.Bytes()))
			}

			return envfile.Parse(string(data))
		}

		envVars, err := loadVars(filePath)
		if err != nil {
			return fmt.Errorf("parsing %s: %w", filePath, err)
		}

		// Filter variables
		selectedVars := crypto.FilterVariables(envVars, filters)

		if len(selectedVars) == 0 {
			fmt.Fprintf(os.Stderr, "⚠️  No variables matched the given filters\n")
			fmt.Fprintf(os.Stderr, "Searched in: %s\n", filePath)
			fmt.Fprintf(os.Stderr, "Filters: %v\n", filters)
			return nil
		}

		// Encrypt and encode
		encoded, err := crypto.EncodeShare(selectedVars, shareWith)
		if err != nil {
			return err
		}

		fmt.Printf("✅ Sharing %d variable(s) with %s\n", len(selectedVars), shortenPublicKey(shareWith))
		fmt.Println()
		fmt.Println("Share this with the recipient:")
		fmt.Println(encoded)
		fmt.Println()
		fmt.Println("Recipient can decrypt with:")
		fmt.Printf("  envvault receive '%s'\n", encoded)

		return nil
	},
}

func readFiltersFromFile(filePath string) ([]string, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", filePath, err)
	}

	var filters []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			filters = append(filters, line)
		}
	}

	return filters, nil
}

func shortenPublicKey(key string) string {
	if len(key) > 20 {
		return key[:10] + "..." + key[len(key)-10:]
	}
	return key
}

func init() {
	shareCmd.Flags().StringVar(&shareWith, "with", "", "Recipient's Age public key (required)")
	shareCmd.Flags().StringVar(&shareVarsFile, "vars-file", "", "File containing variable names (one per line)")
	shareCmd.MarkFlagRequired("with")

	rootCmd.AddCommand(shareCmd)
}
