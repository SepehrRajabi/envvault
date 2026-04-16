package cmd

import (
	"fmt"
	"os"

	"github.com/SepehrRajabi/envvault/crypto"
	"github.com/spf13/cobra"
)

var (
	algorithm string
	listAlgs  bool
)

var lockCmd = &cobra.Command{
	Use:   "lock [file]",
	Short: "Encrypt an .env file into a .env.vault file",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		filePath := args[0]

		data, err := os.ReadFile(filePath)
		if err != nil {
			return fmt.Errorf("reading %s: %w", filePath, err)
		}

		password, err := crypto.ReadPassword("Enter password: ")
		if err != nil {
			return err
		}

		confirm, err := crypto.ReadPassword("Confirm password: ")
		if err != nil {
			return err
		}
		if string(password) != string(confirm) {
			return fmt.Errorf("passwords do not match")
		}

		var p crypto.Provider
		if algorithm != "" {
			var err error
			p, err = crypto.GetProvider(algorithm)
			if err != nil {
				return fmt.Errorf("unknown algorithm %q: %w", algorithm, err)
			}
		}

		encrypted, err := crypto.Encrypt(data, password, p)
		if err != nil {
			return fmt.Errorf("encrypting: %w", err)
		}

		outPath := filePath + ".vault"
		if err := os.WriteFile(outPath, encrypted, 0644); err != nil {
			return fmt.Errorf("writing %s: %w", outPath, err)
		}

		fmt.Printf("🔒 Encrypted %s → %s (AES-256-GCM)\n", filePath, outPath)
		return nil
	},
}

func init() {
	lockCmd.Flags().StringVarP(&algorithm, "algorithm", "a", "",
		"Encryption algorithm (see: envvault algorithms)")
	lockCmd.Flags().BoolVar(&listAlgs, "list-algorithms", false,
		"List available algorithms and exit")
	rootCmd.AddCommand(lockCmd)
}
