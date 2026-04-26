package cmd

import (
	"fmt"
	"os"

	"github.com/SepehrRajabi/envvault/crypto"
	"github.com/SepehrRajabi/envvault/history"
	"github.com/spf13/cobra"
)

var (
	from   string
	to     string
	output string
)

var migrateCmd = &cobra.Command{
	Use:   "migrate [vault-file]",
	Short: "Change the encryption algorithm of an existing vault file",
	Long:  "Migrate allows you to change the encryption algorithm of an existing vault file. ",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		filePath := args[0]

		// 1. Read the vault file
		data, err := os.ReadFile(filePath)
		if err != nil {
			return fmt.Errorf("reading %s: %w", filePath, err)
		}

		// 2. Get credentials (handles password prompt OR age-pubkey automatically)
		password, err := getVaultCredentials(data, filePath)
		if err != nil {
			return err
		}

		// 3. Decrypt with old algorithm
		var oldProvider crypto.Provider
		if from != "" {
			oldProvider, err = crypto.GetProvider(from)
			if err != nil {
				return fmt.Errorf("unknown old algorithm %q: %w", from, err)
			}
		}
		decrypted, err := crypto.Decrypt(data, password, oldProvider)
		if err != nil {
			return fmt.Errorf("decryption failed: %w", err)
		}

		// 4. Encrypt with new algorithm
		var newProvider crypto.Provider
		if to != "" {
			newProvider, err = crypto.GetProvider(to)
			if err != nil {
				return fmt.Errorf("unknown new algorithm %q: %w", to, err)
			}
		} else {
			newProvider = oldProvider
		}
		encrypted, err := crypto.Encrypt(decrypted, password, newProvider)
		if err != nil {
			return fmt.Errorf("encryption failed: %w", err)
		}

		// 5. Write back to file
		if output != "" {
			err := atomicWrite(output, encrypted)
			if err != nil {
				return fmt.Errorf("writing %s: %w", output, err)
			}
			fmt.Printf("Successfully migrated %s to %s with new encryption algorithm\n", filePath, output)

			_ = history.Record("Migrate", filePath, to)

			return nil
		}
		if err := atomicWrite(filePath, encrypted); err != nil {
			return fmt.Errorf("writing %s: %w", filePath, err)
		}

		fmt.Printf("Successfully migrated %s to new encryption algorithm\n", filePath)

		_ = history.Record("Migrate", filePath, to)

		return nil
	},
}

func init() {
	migrateCmd.Flags().StringVar(&from, "from", "", "Current encryption algorithm (optional, will auto-detect if not provided)")
	migrateCmd.Flags().StringVar(&to, "to", "", "New encryption algorithm (optional, defaults to same as old)")
	migrateCmd.Flags().StringVar(&output, "output", "", "Output file for the migrated vault (optional)")

	rootCmd.AddCommand(migrateCmd)
}
