package cmd

import (
	"fmt"
	"net"
	"net/url"
	"os"

	"github.com/SepehrRajabi/envvault/config"
	"github.com/SepehrRajabi/envvault/history"
	"github.com/SepehrRajabi/envvault/keyring"
)

// historyTokenKeyringKey is the keyring key under which the remote history
// backend's auth token is stored, keeping it out of the plaintext config file.
const historyTokenKeyringKey = "history-http-token"

// validateHistoryEndpoint requires https for the remote history backend, with
// plain http allowed only for loopback hosts (local collectors, tests).
// Events carry file paths and the auth token is a bearer credential, so
// neither should cross the network in cleartext.
func validateHistoryEndpoint(endpoint string) error {
	u, err := url.Parse(endpoint)
	if err != nil || u.Host == "" {
		return fmt.Errorf("history.endpoint %q is not a valid URL", endpoint)
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		host := u.Hostname()
		if host == "localhost" {
			return nil
		}
		if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
			return nil
		}
	}
	return fmt.Errorf("history.endpoint %q must use https (http is only allowed for localhost)", endpoint)
}

// configureHistoryBackend selects the history.Backend implementation based
// on the user's config. It's best-effort: a broken config falls back to the
// local backend rather than blocking command execution.
func configureHistoryBackend() {
	cfg, err := config.Load()
	if err != nil {
		return
	}

	switch cfg.History.Backend {
	case "", "local":
		return // already the default
	case "http":
		if cfg.History.Endpoint == "" {
			fmt.Fprintln(os.Stderr, "⚠️  history.backend is \"http\" but history.endpoint is not set; using local history instead.")
			return
		}
		if err := validateHistoryEndpoint(cfg.History.Endpoint); err != nil {
			fmt.Fprintf(os.Stderr, "⚠️  %v; using local history instead.\n", err)
			return
		}
		token, _ := keyring.RetrieveExact(historyTokenKeyringKey)
		history.SetBackend(history.NewHTTPBackend(cfg.History.Endpoint, token))
	default:
		fmt.Fprintf(os.Stderr, "⚠️  unknown history.backend %q; using local history instead.\n", cfg.History.Backend)
	}
}
