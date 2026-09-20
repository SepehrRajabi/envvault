package cmd

import (
	"fmt"
	"os"

	"github.com/SepehrRajabi/envvault/config"
	"github.com/SepehrRajabi/envvault/history"
	"github.com/SepehrRajabi/envvault/keyring"
)

// historyTokenKeyringKey is the keyring key under which the remote history
// backend's auth token is stored, keeping it out of the plaintext config file.
const historyTokenKeyringKey = "history-http-token"

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
		token, _ := keyring.RetrieveExact(historyTokenKeyringKey)
		history.SetBackend(history.NewHTTPBackend(cfg.History.Endpoint, token))
	default:
		fmt.Fprintf(os.Stderr, "⚠️  unknown history.backend %q; using local history instead.\n", cfg.History.Backend)
	}
}
