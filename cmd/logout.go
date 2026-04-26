package cmd

import (
	"fmt"

	"github.com/SepehrRajabi/envvault/keyring"
	"github.com/spf13/cobra"
)

var logoutCmd = &cobra.Command{
	Use:   "logout",
	Short: "Remove decryption key from OS keystore",
	Long:  "Delete your decryption key from the native OS keystore. You'll need to run 'envvault login' again or use --key flag.",
	RunE: func(cmd *cobra.Command, args []string) error {
		return handleLogout()
	},
}

func handleLogout() error {
	if !keyring.HasKey() {
		fmt.Println("No stored key found in OS keystore")
		return nil
	}

	if err := keyring.DeleteKey(); err != nil {
		return err
	}

	fmt.Println("✓ Decryption key removed from OS keystore")
	return nil
}

func init() {
	rootCmd.AddCommand(logoutCmd)
}
