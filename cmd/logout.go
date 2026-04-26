package cmd

import (
	"fmt"

	"github.com/SepehrRajabi/envvault/history"
	"github.com/SepehrRajabi/envvault/keyring"
	"github.com/spf13/cobra"
)

var logoutCmd = &cobra.Command{
	Use:   "logout [vault-file]",
	Short: "Remove decryption key from OS keystore",
	Long: `Delete your decryption key from the native OS keystore.

If [vault-file] is provided, removes the key stored for that specific project.
If no file is provided, removes the default key.

You'll need to run 'envvault login' again or use --key flag to decrypt vaults.`,
	Args: cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		filePath := ""
		if len(args) > 0 {
			filePath = args[0]
		}
		return handleLogout(filePath)
	},
}

func handleLogout(filePath string) error {
	if !keyring.HasKey(filePath) {
		if filePath != "" {
			fmt.Printf("No stored key found in OS keystore for %s\n", filePath)
		} else {
			fmt.Println("No stored default key found in OS keystore")
		}
		return nil
	}

	if err := keyring.DeleteKey(filePath); err != nil {
		return err
	}

	if filePath != "" {
		fmt.Printf("✅ Decryption key removed from OS keystore for %s\n", filePath)
		_ = history.Record("Logout", filePath, "")
	} else {
		fmt.Println("✅ Default decryption key removed from OS keystore")
		_ = history.Record("Logout", "OS keystore", "")
	}

	return nil
}

func init() {
	rootCmd.AddCommand(logoutCmd)
}
