package cmd

import (
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "envvault",
	Short: "Encrypted .env file manager",
	Long:  "Lock, unlock, diff, and share .env files securely across your team.",
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().Bool("verbose", false, "verbose output")
}
