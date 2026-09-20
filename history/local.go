package history

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
)

const (
	maxLocalEvents = 1000
	localDirName   = ".envvault"
	localFileName  = "history.json"
)

// localBackend stores events in a JSON file under the user's home directory.
type localBackend struct {
	mu sync.Mutex
}

// NewLocalBackend builds a Backend that stores events in a JSON file under
// the user's home directory (~/.envvault/history.json).
func NewLocalBackend() Backend {
	return &localBackend{}
}

func localHistoryPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("finding home directory: %w", err)
	}
	return filepath.Join(home, localDirName, localFileName), nil
}

func (b *localBackend) Record(e Event) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	path, err := localHistoryPath()
	if err != nil {
		return err
	}

	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return fmt.Errorf("creating history directory: %w", err)
	}

	events, err := readLocalEvents(path)
	if err != nil {
		return err
	}

	events = append(events, e)

	// Cap the size (keep the most recent maxLocalEvents)
	if len(events) > maxLocalEvents {
		events = events[len(events)-maxLocalEvents:]
	}

	return writeLocalEvents(path, events)
}

func (b *localBackend) List(limit int) ([]Event, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	path, err := localHistoryPath()
	if err != nil {
		return nil, err
	}

	events, err := readLocalEvents(path)
	if err != nil {
		return nil, err
	}

	// Return newest first
	sort.Slice(events, func(i, j int) bool {
		return events[i].Timestamp.After(events[j].Timestamp)
	})

	if limit > 0 && limit < len(events) {
		events = events[:limit]
	}

	return events, nil
}

func (b *localBackend) Clear() error {
	b.mu.Lock()
	defer b.mu.Unlock()

	path, err := localHistoryPath()
	if err != nil {
		return err
	}

	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("clearing history: %w", err)
	}

	return nil
}

func readLocalEvents(path string) ([]Event, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return []Event{}, nil // First run, no history yet
		}
		return nil, fmt.Errorf("reading history: %w", err)
	}

	if len(data) == 0 {
		return []Event{}, nil
	}

	var events []Event
	if err := json.Unmarshal(data, &events); err != nil {
		return nil, fmt.Errorf("parsing history: %w", err)
	}

	return events, nil
}

func writeLocalEvents(path string, events []Event) error {
	data, err := json.MarshalIndent(events, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling history: %w", err)
	}

	// Write with 0600 permissions since it contains sensitive metadata
	return os.WriteFile(path, data, 0600)
}
