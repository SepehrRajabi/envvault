package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/SepehrRajabi/envvault/config"
)

func TestConfigFlagOverridesConfigPath(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("ENVVAULT_CONFIG", "")
	t.Cleanup(func() { config.SetPathOverride("") })

	custom := filepath.Join(t.TempDir(), "custom.toml")
	content := "version = \"custom\"\n"
	if err := os.WriteFile(custom, []byte(content), 0600); err != nil {
		t.Fatalf("writing custom config: %v", err)
	}

	configFlagPath = custom
	t.Cleanup(func() { configFlagPath = "" })

	rootCmd.PersistentPreRun(rootCmd, nil)

	path, err := config.GetConfigPath()
	if err != nil {
		t.Fatalf("GetConfigPath: %v", err)
	}
	if path != custom {
		t.Fatalf("expected --config to override the config path to %q, got %q", custom, path)
	}

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Version != "custom" {
		t.Fatalf("expected config loaded from --config path, got version %q", cfg.Version)
	}
}

func TestNoConfigFlagLeavesDefaultConfigPath(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("ENVVAULT_CONFIG", "")
	t.Cleanup(func() { config.SetPathOverride("") })

	configFlagPath = ""
	rootCmd.PersistentPreRun(rootCmd, nil)

	path, err := config.GetConfigPath()
	if err != nil {
		t.Fatalf("GetConfigPath: %v", err)
	}
	want := filepath.Join(home, ".config", "envvault", "config.toml")
	if path != want {
		t.Fatalf("expected default config path %q, got %q", want, path)
	}
}
