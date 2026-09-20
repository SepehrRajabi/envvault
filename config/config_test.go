package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGetConfigPathDefaultsToHomeConfigDir(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("ENVVAULT_CONFIG", "")
	SetPathOverride("")

	path, err := GetConfigPath()
	if err != nil {
		t.Fatalf("GetConfigPath: %v", err)
	}

	want := filepath.Join(home, ".config", "envvault", "config.toml")
	if path != want {
		t.Fatalf("got %q, want %q", path, want)
	}
}

func TestGetConfigPathUsesEnvVar(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	SetPathOverride("")

	want := filepath.Join(t.TempDir(), "custom.toml")
	t.Setenv("ENVVAULT_CONFIG", want)

	path, err := GetConfigPath()
	if err != nil {
		t.Fatalf("GetConfigPath: %v", err)
	}
	if path != want {
		t.Fatalf("got %q, want %q", path, want)
	}
}

func TestGetConfigPathOverrideTakesPrecedenceOverEnvVar(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("ENVVAULT_CONFIG", "/should-not-be-used.toml")

	override := filepath.Join(t.TempDir(), "override.toml")
	SetPathOverride(override)
	t.Cleanup(func() { SetPathOverride("") })

	path, err := GetConfigPath()
	if err != nil {
		t.Fatalf("GetConfigPath: %v", err)
	}
	if path != override {
		t.Fatalf("got %q, want %q", path, override)
	}
}

func TestLoadReadsFromOverriddenPath(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("ENVVAULT_CONFIG", "")

	custom := filepath.Join(t.TempDir(), "custom.toml")
	content := "version = \"custom\"\n\n[sharing]\ndefault_format = \"json\"\n"
	if err := os.WriteFile(custom, []byte(content), 0600); err != nil {
		t.Fatalf("writing custom config: %v", err)
	}

	SetPathOverride(custom)
	t.Cleanup(func() { SetPathOverride("") })

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Version != "custom" {
		t.Fatalf("expected version %q from overridden config, got %q", "custom", cfg.Version)
	}
	if cfg.Sharing.DefaultFormat != "json" {
		t.Fatalf("expected sharing.default_format %q from overridden config, got %q", "json", cfg.Sharing.DefaultFormat)
	}
}

func TestLoadFallsBackToDefaultsWhenOverriddenPathMissing(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("ENVVAULT_CONFIG", "")

	SetPathOverride(filepath.Join(t.TempDir(), "does-not-exist.toml"))
	t.Cleanup(func() { SetPathOverride("") })

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Encryption.DefaultAlgorithm != defaultConfig.Encryption.DefaultAlgorithm {
		t.Fatalf("expected defaults when overridden path doesn't exist, got %+v", cfg)
	}
}
