package cmd

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/SepehrRajabi/envvault/config"
	"github.com/SepehrRajabi/envvault/history"
	"github.com/SepehrRajabi/envvault/keyring"
	kr "github.com/zalando/go-keyring"
)

func restoreLocalHistoryBackend(t *testing.T) {
	t.Helper()
	t.Cleanup(func() { history.SetBackend(history.NewLocalBackend()) })
}

func TestConfigureHistoryBackendDefaultsToLocal(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	restoreLocalHistoryBackend(t)

	configureHistoryBackend()

	if err := history.Record("Lock", "a.env.vault", ""); err != nil {
		t.Fatalf("Record: %v", err)
	}
	events, err := history.List(0)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected local backend to have recorded the event, got %d events", len(events))
	}
}

func TestConfigureHistoryBackendSelectsHTTP(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	restoreLocalHistoryBackend(t)
	kr.MockInit()

	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	if err := keyring.StoreKey("s3cr3t-token", historyTokenKeyringKey); err != nil {
		t.Fatalf("seed keyring: %v", err)
	}

	cfg := *config.GetDefault()
	cfg.History.Backend = "http"
	cfg.History.Endpoint = srv.URL
	if err := config.Save(&cfg); err != nil {
		t.Fatalf("saving config: %v", err)
	}

	configureHistoryBackend()

	if err := history.Record("Lock", "a.env.vault", ""); err != nil {
		t.Fatalf("Record: %v", err)
	}
	if gotAuth != "Bearer s3cr3t-token" {
		t.Fatalf("expected http backend to send the stored token, got Authorization=%q", gotAuth)
	}
}

func TestConfigureHistoryBackendHTTPWithoutEndpointFallsBackToLocal(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	restoreLocalHistoryBackend(t)

	cfg := *config.GetDefault()
	cfg.History.Backend = "http"
	cfg.History.Endpoint = ""
	if err := config.Save(&cfg); err != nil {
		t.Fatalf("saving config: %v", err)
	}

	stderr := captureStderr(t, configureHistoryBackend)
	if !strings.Contains(stderr, "history.endpoint is not set") {
		t.Fatalf("expected warning about missing endpoint, got:\n%s", stderr)
	}

	if err := history.Record("Lock", "a.env.vault", ""); err != nil {
		t.Fatalf("expected local fallback to still record events: %v", err)
	}
}

func TestConfigureHistoryBackendUnknownBackendFallsBackToLocal(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	restoreLocalHistoryBackend(t)

	cfg := *config.GetDefault()
	cfg.History.Backend = "carrier-pigeon"
	if err := config.Save(&cfg); err != nil {
		t.Fatalf("saving config: %v", err)
	}

	stderr := captureStderr(t, configureHistoryBackend)
	if !strings.Contains(stderr, "unknown history.backend") {
		t.Fatalf("expected warning about unknown backend, got:\n%s", stderr)
	}

	if err := history.Record("Lock", "a.env.vault", ""); err != nil {
		t.Fatalf("expected local fallback to still record events: %v", err)
	}
}
