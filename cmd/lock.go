package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/SepehrRajabi/envvault/crypto"
	"github.com/SepehrRajabi/envvault/history"
	"github.com/spf13/cobra"
)

var (
	algorithm string
	listAlgs  bool
	allowWeak bool
	recipient []string
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

		var password []byte

		// Mode 1: Public Key Encryption
		if len(recipient) > 0 {
			if algorithm != "" && algorithm != "age-pubkey" {
				return fmt.Errorf("cannot use --recipient with algorithm %s (must be age-pubkey)", algorithm)
			}
			algorithm = "age-pubkey"
			password = []byte(strings.Join(recipient, ","))
		} else {
			// Mode 2: Password Encryption
			password, err = crypto.GetPassword("Enter password: ")
			if err != nil {
				return err
			}

			confirm, err := crypto.GetPassword("Confirm password: ")
			if err != nil {
				return err
			}
			if string(password) != string(confirm) {
				return fmt.Errorf("passwords do not match")
			}

			if err := crypto.CheckPasswordStrength(password, allowWeak); err != nil {
				return err
			}
		}

		var p crypto.Provider
		if algorithm != "" {
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

		algID := "aes256gcm-argon2id"
		if p != nil {
			algID = p.AlgorithmID()
		} else if def := crypto.Default(); def != nil {
			algID = def.AlgorithmID()
		}

		fmt.Printf("🔒 Encrypted %s → %s (%s)\n", filePath, outPath, algID)
		_ = history.Record("Lock", outPath, algID)
		return nil
	},
}

func init() {
	lockCmd.Flags().StringVarP(&algorithm, "algorithm", "a", "", "Encryption algorithm (see: envvault algorithms)")
	lockCmd.Flags().BoolVar(&listAlgs, "list-algorithms", false, "List available algorithms and exit")
	lockCmd.Flags().BoolVar(&allowWeak, "allow-weak", false, "Allow weak passwords (not recommended)")
	lockCmd.Flags().StringArrayVarP(&recipient, "recipient", "r", nil, "Age public key(s) (age1...) for public key encryption (can be specified multiple times)")

	rootCmd.AddCommand(lockCmd)
}
