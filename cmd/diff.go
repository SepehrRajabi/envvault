package cmd

import (
	"fmt"
	"os"

	"github.com/SepehrRajabi/envvault/crypto"
	"github.com/SepehrRajabi/envvault/envfile"
	"github.com/spf13/cobra"
)

var diffCmd = &cobra.Command{
	Use:   "diff [file1] [file2]",
	Short: "Compare two .env or .env.vault files by key",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		// Shared password cache to avoid double-prompting
		var cachedPassword []byte

		// Loader function
		loadVars := func(filePath string) ([]envfile.EnvVar, error) {
			data, err := os.ReadFile(filePath)
			if err != nil {
				return nil, fmt.Errorf("reading %s: %w", filePath, err)
			}

			// Detect if it's a vault file
			if isVaultFile(filePath, data) {
				password := cachedPassword

				// If we don't have a password yet, get it
				if password == nil {
					pswd, err := crypto.GetPassword("Enter password for " + filePath + ": ")
					if err != nil {
						return nil, err
					}
					password = pswd
				}

				// Try to decrypt
				var p crypto.Provider
				if algorithm != "" {
					var err error
					p, err = crypto.GetProvider(algorithm)
					if err != nil {
						return nil, fmt.Errorf("unknown algorithm %q: %w", algorithm, err)
					}
				}
				decrypted, err := crypto.Decrypt(data, password, p)
				if err != nil {
					// If decryption fails and we used a cached password,
					// maybe the second file has a different password. Prompt again.
					if cachedPassword != nil {
						fmt.Fprintf(os.Stderr, "⚠️  Password for %s didn't match. Trying again...\n", filePath)
						password, err = crypto.GetPassword("Enter password for " + filePath + ": ")
						if err != nil {
							return nil, err
						}
						decrypted, err = crypto.Decrypt(data, password, p)
						if err != nil {
							return nil, fmt.Errorf("decryption failed for %s: %w", filePath, err)
						}
					} else {
						return nil, fmt.Errorf("decryption failed for %s: %w", filePath, err)
					}
				}

				// Cache the successful password for the next file
				cachedPassword = password

				return envfile.Parse(string(decrypted))
			}

			return envfile.Parse(string(data))
		}

		varsA, err := loadVars(args[0])
		if err != nil {
			return err
		}
		varsB, err := loadVars(args[1])
		if err != nil {
			return err
		}

		added, removed, changed := envfile.Diff(varsA, varsB)
		output := envfile.FormatDiff(added, removed, changed)

		if output == "" {
			fmt.Println("✅ No differences found")
			return nil
		}

		fmt.Printf("Comparing %s ↔ %s:\n\n", args[0], args[1])
		fmt.Print(output)

		fmt.Printf("\n%d added, %d removed, %d changed\n",
			len(added), len(removed), len(changed))
		return nil
	},
}

func init() {
	rootCmd.AddCommand(diffCmd)
}
