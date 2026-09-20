// Package cmd implements envvault's CLI commands (lock, unlock, edit,
// rotate, diff, share, history, config, ...) as cobra commands registered
// on rootCmd. Execute is the sole entry point, called from main.
package cmd

import (
	"os"

	"github.com/SepehrRajabi/envvault/config"
	"github.com/spf13/cobra"
)

var configFlagPath string

var rootCmd = &cobra.Command{
	Use:   "envvault",
	Short: "Encrypted .env file manager",
	Long:  "Lock, unlock, diff, and share .env files securely across your team.",
	// Runs once flags are parsed but before any subcommand's RunE, so
	// --config is applied before anything (including history backend
	// selection) reads config.Load().
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		if configFlagPath != "" {
			config.SetPathOverride(configFlagPath)
		}
		configureHistoryBackend()
	},
}

// Execute parses os.Args and runs the matched envvault subcommand, exiting
// with status 1 on error. It's the only function main is expected to call.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().Bool("verbose", false, "verbose output")
	rootCmd.PersistentFlags().StringVar(&configFlagPath, "config", "", "Path to config file (overrides ENVVAULT_CONFIG and the default ~/.config/envvault/config.toml)")
}
