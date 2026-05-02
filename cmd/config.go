package cmd

import (
	"fmt"
	"os"

	"github.com/SepehrRajabi/envvault/config"
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

	fmt.Println("\n⚙️  envvault Configuration")
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

	path, _ := config.GetConfigPath()
	fmt.Printf("\nConfig file: %s\n", path)
	if _, err := os.Stat(path); os.IsNotExist(err) {
		fmt.Println("(using defaults - file not created yet)")
	}
	fmt.Println()

	return nil
}

func initConfig() error {
	defaultCfg := config.GetDefault()
	if err := config.Save(defaultCfg); err != nil {
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
