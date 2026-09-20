package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/SepehrRajabi/envvault/history"
	"github.com/SepehrRajabi/envvault/keyring"
	kr "github.com/zalando/go-keyring"
)

func resetHistoryFlags() {
	historyLimit = 10
	historyClear = false
	historySetToken = ""
}

func TestHistoryCommandListsRecordedEvents(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	resetHistoryFlags()
	t.Cleanup(resetHistoryFlags)

	if err := history.Record("Lock", "my.env.vault", "aes256gcm-argon2id"); err != nil {
		t.Fatalf("history.Record: %v", err)
	}

	out := captureStdout(t, func() {
		if err := historyCmd.RunE(historyCmd, nil); err != nil {
			t.Fatalf("history: %v", err)
		}
	})

	if !strings.Contains(out, "my.env.vault") {
		t.Fatalf("expected history output to include recorded file, got:\n%s", out)
	}
}

func TestHistoryCommandLimitFlag(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	resetHistoryFlags()
	t.Cleanup(resetHistoryFlags)

	for i := 0; i < 5; i++ {
		if err := history.Record("Lock", "file.env.vault", "aes256gcm-argon2id"); err != nil {
			t.Fatalf("history.Record: %v", err)
		}
	}

	historyLimit = 2
	out := captureStdout(t, func() {
		if err := historyCmd.RunE(historyCmd, nil); err != nil {
			t.Fatalf("history --limit 2: %v", err)
		}
	})

	if !strings.Contains(out, "Showing 2 most recent events") {
		t.Fatalf("expected output to report 2 events shown, got:\n%s", out)
	}
}

func TestHistoryCommandClearRemovesFile(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	resetHistoryFlags()
	t.Cleanup(resetHistoryFlags)

	if err := history.Record("Lock", "file.env.vault", ""); err != nil {
		t.Fatalf("history.Record: %v", err)
	}

	home, _ := os.UserHomeDir()
	historyPath := filepath.Join(home, ".envvault", "history.json")
	if _, err := os.Stat(historyPath); err != nil {
		t.Fatalf("expected history file to exist before clear: %v", err)
	}

	historyClear = true
	if err := historyCmd.RunE(historyCmd, nil); err != nil {
		t.Fatalf("history --clear: %v", err)
	}

	if _, err := os.Stat(historyPath); !os.IsNotExist(err) {
		t.Fatalf("expected history file to be removed, stat err=%v", err)
	}
}

func TestHistoryCommandSetTokenStoresInKeyring(t *testing.T) {
	kr.MockInit()
	resetHistoryFlags()
	t.Cleanup(resetHistoryFlags)

	historySetToken = "s3cr3t-token"
	out := captureStdout(t, func() {
		if err := historyCmd.RunE(historyCmd, nil); err != nil {
			t.Fatalf("history --set-token: %v", err)
		}
	})

	if !strings.Contains(out, "stored") {
		t.Fatalf("expected confirmation message, got:\n%s", out)
	}

	stored, err := keyring.RetrieveExact(historyTokenKeyringKey)
	if err != nil {
		t.Fatalf("RetrieveKey: %v", err)
	}
	if stored != "s3cr3t-token" {
		t.Fatalf("expected stored token %q, got %q", "s3cr3t-token", stored)
	}
}
