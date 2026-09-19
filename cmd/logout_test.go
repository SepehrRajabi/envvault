package cmd

import (
	"strings"
	"testing"

	"github.com/SepehrRajabi/envvault/keyring"
	kr "github.com/zalando/go-keyring"
)

// Every test in this file uses kr.MockInit(), which swaps go-keyring's
// backend for an in-memory store. Without it, these tests would read from
// and write to the real OS keychain on whatever machine runs them.
func TestLogoutCommandRemovesStoredKey(t *testing.T) {
	kr.MockInit()

	if err := keyring.StoreKey("s3cr3t", "project.env.vault"); err != nil {
		t.Fatalf("seed keyring: %v", err)
	}

	out := captureStdout(t, func() {
		if err := handleLogout("project.env.vault"); err != nil {
			t.Fatalf("logout: %v", err)
		}
	})
	if !strings.Contains(out, "removed") {
		t.Fatalf("expected confirmation message, got:\n%s", out)
	}

	if keyring.HasKey("project.env.vault") {
		t.Fatal("expected key to be removed from keyring after logout")
	}
}

func TestLogoutCommandNoStoredKeyIsNotAnError(t *testing.T) {
	kr.MockInit()

	if err := handleLogout("nonexistent.env.vault"); err != nil {
		t.Fatalf("expected logout with no stored key to succeed, got %v", err)
	}
}

func TestLogoutCommandDefaultKey(t *testing.T) {
	kr.MockInit()

	if err := keyring.StoreKey("default-secret", ""); err != nil {
		t.Fatalf("seed default keyring key: %v", err)
	}

	if err := handleLogout(""); err != nil {
		t.Fatalf("logout (default): %v", err)
	}
	if keyring.HasKey("") {
		t.Fatal("expected default key to be removed")
	}
}
