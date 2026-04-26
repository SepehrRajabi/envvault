package cmd

import (
	"fmt"
	"syscall"

	"github.com/SepehrRajabi/envvault/history"
	"github.com/SepehrRajabi/envvault/keyring"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

var loginCmd = &cobra.Command{
	Use:   "login [vault-file]",
	Short: "Store decryption key in OS keystore",
	Long: `Securely store your decryption key in the native OS keystore (macOS Keychain, Windows Credential Manager, Linux Secret Service).

This allows you to use envvault commands without specifying --key or entering your password repeatedly.

If [vault-file] is provided, the key is stored per-project. Future commands automatically use the stored key for that file.
If no file is provided, stores as the default key (used as fallback for all projects).`,
	Args: cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		filePath := ""
		if len(args) > 0 {
			filePath = args[0]
		}
		return handleLogin(filePath)
	},
}

func handleLogin(filePath string) error {
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
	if err := keyring.StoreKey(key, filePath); err != nil {
		return err
	}

	if filePath != "" {
		fmt.Printf("✅ Decryption key stored securely in OS keystore for %s\n", filePath)
		_ = history.Record("Login", filePath, "")
	} else {
		fmt.Println("✅ Default decryption key stored securely in OS keystore")
		_ = history.Record("Login", "OS keystore", "")
	}
	return nil
}

func init() {
	rootCmd.AddCommand(loginCmd)
}
