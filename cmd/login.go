package cmd

import (
	"fmt"
	"syscall"

	"github.com/SepehrRajabi/envvault/keyring"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

var loginCmd = &cobra.Command{
	Use:   "login",
	Short: "Store decryption key in OS keystore",
	Long: `Securely store your decryption key in the native OS keystore (macOS Keychain, Windows Credential Manager, Linux Secret Service).
This allows you to use envvault commands without specifying --key or entering your password repeatedly.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return handleLogin()
	},
}

func handleLogin() error {
	fmt.Print("Enter your decryption key (password): ")

	// Read password securely without echoing
	bytePassword, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		return fmt.Errorf("failed to read password: %w", err)
	}
	fmt.Println() // Add newline after password input

	key := string(bytePassword)
	if key == "" {
		return fmt.Errorf("key cannot be empty")
	}

	// Store in OS keyring
	if err := keyring.StoreKey(key); err != nil {
		return err
	}

	fmt.Println("✅ Decryption key stored securely in OS keystore")
	return nil
}

func init() {
	rootCmd.AddCommand(loginCmd)
}
