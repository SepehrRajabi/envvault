package config

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/BurntSushi/toml"
)

type Config struct {
	Encryption  EncryptionConfig  `toml:"encryption"`
	Sharing     SharingConfig     `toml:"sharing"`
	Integration IntegrationConfig `toml:"integration"`
}

type EncryptionConfig struct {
	DefaultAlgorithm   string   `toml:"default_algorithm"`
	DefaultRecipients  []string `toml:"default_recipients"`
	AllowWeakPasswords bool     `toml:"allow_weak_passwords"`
}

type SharingConfig struct {
	DefaultFormat string `toml:"default_format"`
}

type IntegrationConfig struct {
	GitignoreEnabled bool `toml:"gitignore_enabled"`
	PreCommitEnabled bool `toml:"precommit_enabled"`
}

var (
	defaultConfig = Config{
		Encryption: EncryptionConfig{
			DefaultAlgorithm:   "aes256gcm-argon2id",
			DefaultRecipients:  []string{},
			AllowWeakPasswords: false,
		},
		Sharing: SharingConfig{
			DefaultFormat: "shell",
		},
		Integration: IntegrationConfig{
			GitignoreEnabled: true,
			PreCommitEnabled: false,
		},
	}
)

// GetConfigPath returns the path to the envvault config file
func GetConfigPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".config", "envvault", "config.toml"), nil
}

// Load reads the config file and returns a Config struct
func Load() (*Config, error) {
	configPath, err := GetConfigPath()
	if err != nil {
		return nil, err
	}

	// Return defaults if config doesn't exist
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return &defaultConfig, nil
	}

	var cfg Config
	if _, err := toml.DecodeFile(configPath, &cfg); err != nil {
		return nil, fmt.Errorf("reading config file: %w", err)
	}

	return &cfg, nil
}

// Save writes the config to the config file
func Save(cfg *Config) error {
	configPath, err := GetConfigPath()
	if err != nil {
		return err
	}

	// Ensure the directory exists
	if err := os.MkdirAll(filepath.Dir(configPath), 0755); err != nil {
		return fmt.Errorf("creating config directory: %w", err)
	}

	// Write the config
	file, err := os.Create(configPath)
	if err != nil {
		return fmt.Errorf("creating config file: %w", err)
	}
	defer file.Close()

	if err := toml.NewEncoder(file).Encode(cfg); err != nil {
		return fmt.Errorf("writing config file: %w", err)
	}

	return nil
}

// GetDefault returns the default config (for comparison/reset)
func GetDefault() *Config {
	return &defaultConfig
}
