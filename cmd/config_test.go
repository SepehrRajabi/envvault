package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/SepehrRajabi/envvault/config"
)

func TestConfigCommandInitCreatesFile(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	if err := initConfig(); err != nil {
		t.Fatalf("config --init: %v", err)
	}

	path, err := config.GetConfigPath()
	if err != nil {
		t.Fatalf("GetConfigPath: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("expected config file to be created: %v", err)
	}
}

func TestConfigCommandResetRemovesFile(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	if err := initConfig(); err != nil {
		t.Fatalf("config --init: %v", err)
	}
	path, _ := config.GetConfigPath()

	if err := resetConfig(); err != nil {
		t.Fatalf("config --reset: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("expected config file to be removed after reset, stat err=%v", err)
	}
}

func TestConfigCommandShowPathPrintsConfigPath(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	out := captureStdout(t, func() {
		if err := showConfigPath(); err != nil {
			t.Fatalf("config --path: %v", err)
		}
	})

	path, _ := config.GetConfigPath()
	if strings.TrimSpace(out) != path {
		t.Fatalf("expected output to be config path %q, got %q", path, out)
	}
}

func TestConfigCommandShowUsesDefaultsWhenNoFile(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	out := captureStdout(t, func() {
		if err := showConfig(); err != nil {
			t.Fatalf("config: %v", err)
		}
	})

	if out == "" {
		t.Fatal("expected non-empty config output")
	}
	if !strings.Contains(out, fullVersion()) {
		t.Fatalf("expected config output to include the version, got:\n%s", out)
	}
}

func TestConfigCommandInitStampsCurrentVersion(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	if err := initConfig(); err != nil {
		t.Fatalf("config --init: %v", err)
	}

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Version != fullVersion() {
		t.Fatalf("expected freshly initialized config to have version %q, got %q", fullVersion(), cfg.Version)
	}
}

func TestConfigCommandShowFallsBackToCurrentVersionForLegacyFile(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	path, err := config.GetConfigPath()
	if err != nil {
		t.Fatalf("GetConfigPath: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatalf("mkdir config dir: %v", err)
	}
	// A config.toml written before the version field existed has no
	// [version] key at all, so config.Load() leaves cfg.Version == "".
	legacyContent := "[encryption]\n  default_algorithm = \"aes256gcm-argon2id\"\n"
	if err := os.WriteFile(path, []byte(legacyContent), 0600); err != nil {
		t.Fatalf("write legacy config: %v", err)
	}

	out := captureStdout(t, func() {
		if err := showConfig(); err != nil {
			t.Fatalf("config: %v", err)
		}
	})
	if !strings.Contains(out, fullVersion()) {
		t.Fatalf("expected show to fall back to the running version for a legacy config, got:\n%s", out)
	}
}
