package cmd

import (
	"fmt"
	"os"

	"github.com/SepehrRajabi/envvault/config"
	"github.com/SepehrRajabi/envvault/keyring"
	"github.com/spf13/cobra"
)

var (
	configShow  bool
	configInit  bool
	configReset bool
	configPath  bool
)

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Manage envvault configuration",
	Long:  "View, initialize, or reset the envvault configuration file at ~/.config/envvault/config.toml",
	RunE: func(cmd *cobra.Command, args []string) error {
		if configInit {
			return initConfig()
		}
		if configReset {
			return resetConfig()
		}
		if configPath {
			return showConfigPath()
		}
		// Default: show config
		return showConfig()
	},
}

func showConfig() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}

	// Config files written before the version field existed (or the
	// in-memory defaults, which don't carry one either) have no version
	// recorded; report the running binary's version for those rather than
	// showing it blank.
	displayVersion := cfg.Version
	if displayVersion == "" {
		displayVersion = fullVersion()
	}

	fmt.Println("\n⚙️  envvault Configuration")
	fmt.Printf("  Version: %s\n", displayVersion)
	fmt.Println(string([]byte{'-'}[0]) + " Encryption Settings")
	fmt.Printf("  Default Algorithm:    %s\n", cfg.Encryption.DefaultAlgorithm)
	fmt.Printf("  Allow Weak Passwords: %v\n", cfg.Encryption.AllowWeakPasswords)
	if len(cfg.Encryption.DefaultRecipients) > 0 {
		fmt.Println("  Default Recipients:")
		for _, recipient := range cfg.Encryption.DefaultRecipients {
			fmt.Printf("    - %s\n", recipient)
		}
	} else {
		fmt.Println("  Default Recipients: (none)")
	}

	fmt.Println("\n- Integration Settings")
	fmt.Printf("  .gitignore Enabled:   %v\n", cfg.Integration.GitignoreEnabled)
	fmt.Printf("  Pre-commit Enabled:   %v\n", cfg.Integration.PreCommitEnabled)

	fmt.Println("\n- Sharing Settings")
	fmt.Printf("  Default Format:       %s\n", cfg.Sharing.DefaultFormat)

	fmt.Println("\n- History Settings")
	backend := cfg.History.Backend
	if backend == "" {
		backend = "local"
	}
	fmt.Printf("  Backend:              %s\n", backend)
	if backend == "http" {
		fmt.Printf("  Endpoint:             %s\n", cfg.History.Endpoint)
		tokenStatus := "not set (envvault history --set-token)"
		if keyring.HasExactKey(historyTokenKeyringKey) {
			tokenStatus = "set"
		}
		fmt.Printf("  Auth Token:           %s\n", tokenStatus)
	}

	path, _ := config.GetConfigPath()
	fmt.Printf("\nConfig file: %s\n", path)
	if _, err := os.Stat(path); os.IsNotExist(err) {
		fmt.Println("(using defaults - file not created yet)")
	}
	fmt.Println()

	return nil
}

func initConfig() error {
	cfg := *config.GetDefault()
	cfg.Version = fullVersion()
	if err := config.Save(&cfg); err != nil {
		return err
	}

	path, _ := config.GetConfigPath()
	fmt.Printf("✅ Initialized config file: %s\n", path)
	fmt.Println("   Edit this file to customize your defaults")
	return nil
}

func resetConfig() error {
	path, _ := config.GetConfigPath()
	if err := os.RemoveAll(path); err != nil {
		return fmt.Errorf("removing config file: %w", err)
	}
	fmt.Printf("✅ Reset to defaults (deleted: %s)\n", path)
	return nil
}

func showConfigPath() error {
	path, err := config.GetConfigPath()
	if err != nil {
		return err
	}
	fmt.Println(path)
	return nil
}

func init() {
	configCmd.Flags().BoolVar(&configShow, "show", false, "Show configuration (default)")
	configCmd.Flags().BoolVar(&configInit, "init", false, "Initialize config file with defaults")
	configCmd.Flags().BoolVar(&configReset, "reset", false, "Reset config to defaults")
	configCmd.Flags().BoolVar(&configPath, "path", false, "Print config file path")

	rootCmd.AddCommand(configCmd)
}
