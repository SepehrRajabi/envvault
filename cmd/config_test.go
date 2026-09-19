package cmd

import (
	"os"
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
}
