package cmd

import (
	"fmt"
	"os"

	"github.com/SepehrRajabi/envvault/crypto"
	"github.com/SepehrRajabi/envvault/history"
	"github.com/spf13/cobra"
)

var rotateAllowWeak bool

var rotateCmd = &cobra.Command{
	Use:   "rotate [vault-file]",
	Short: "Re-encrypt a vault with a new password in-place",
	Long:  "Decrypts a vault file in memory and immediately re-encrypts it with a new password. The unencrypted data never touches the disk.",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		filePath := args[0]

		// 1. Read the vault file
		data, err := os.ReadFile(filePath)
		if err != nil {
			return fmt.Errorf("reading %s: %w", filePath, err)
		}

		// 2. Get the current credentials
		oldPassword, err := getVaultCredentials(data)
		if err != nil {
			return err
		}

		// 3. Decrypt in-memory
		var p crypto.Provider
		if algorithm != "" {
			p, err = crypto.GetProvider(algorithm)
			if err != nil {
				return fmt.Errorf("unknown algorithm %q: %w", algorithm, err)
			}
		}
		plaintext, err := crypto.Decrypt(data, oldPassword, p)
		if err != nil {
			return fmt.Errorf("decryption failed: incorrect password or corrupted file")
		}

		fmt.Println("✅ Vault unlocked successfully. Please enter the new password.")

		// 4. Get the new password (always interactive)
		newPassword, err := crypto.GetPassword("Enter new password: ")
		if err != nil {
			return err
		}

		confirm, err := crypto.GetPassword("Confirm new password: ")
		if err != nil {
			return err
		}
		if string(newPassword) != string(confirm) {
			return fmt.Errorf("new passwords do not match")
		}

		// 5. Check strength of the new password
		if err := crypto.CheckPasswordStrength(newPassword, rotateAllowWeak); err != nil {
			return err
		}

		// 6. Re-encrypt with the new password, using the default algorithm
		newCiphertext, err := crypto.Encrypt(plaintext, newPassword)
		if err != nil {
			return fmt.Errorf("re-encryption failed: %w", err)
		}

		// 7. Atomically overwrite the original file
		if err := atomicWrite(filePath, newCiphertext); err != nil {
			return fmt.Errorf("writing new vault file: %w", err)
		}

		fmt.Printf("✅ Password rotated successfully for %s\n", filePath)
		_ = history.Record("rotate", filePath, "")

		return nil
	},
}

func init() {
	rotateCmd.Flags().BoolVar(&rotateAllowWeak, "allow-weak", false, "Allow weak new passwords (not recommended)")

	rootCmd.AddCommand(rotateCmd)
}
