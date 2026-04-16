package history

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

const (
	maxEvents = 1000
	dirName   = ".envvault"
	fileName  = "history.json"
)

var mu sync.Mutex

type Event struct {
	Timestamp time.Time `json:"timestamp"`
	Action    string    `json:"action"`
	File      string    `json:"file"`
	Algorithm string    `json:"algorithm,omitempty"`
}

func historyPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("finding home directory: %w", err)
	}
	return filepath.Join(home, dirName, fileName), nil
}

// Record adds a new event to the history log.
func Record(action, file, algorithm string) error {
	mu.Lock()
	defer mu.Unlock()

	path, err := historyPath()
	if err != nil {
		return err
	}

	// Ensure directory exists
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return fmt.Errorf("creating history directory: %w", err)
	}

	// Read existing history
	events, err := readEvents(path)
	if err != nil {
		return err
	}

	// Append new event
	events = append(events, Event{
		Timestamp: time.Now(),
		Action:    action,
		File:      file,
		Algorithm: algorithm,
	})

	// Cap the size (keep the most recent maxEvents)
	if len(events) > maxEvents {
		events = events[len(events)-maxEvents:]
	}

	// Write back
	return writeEvents(path, events)
}

// List returns the most recent `limit` events.
func List(limit int) ([]Event, error) {
	mu.Lock()
	defer mu.Unlock()

	path, err := historyPath()
	if err != nil {
		return nil, err
	}

	events, err := readEvents(path)
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

func readEvents(path string) ([]Event, error) {
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

func writeEvents(path string, events []Event) error {
	data, err := json.MarshalIndent(events, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling history: %w", err)
	}

	// Write with 0600 permissions since it contains sensitive metadata
	return os.WriteFile(path, data, 0600)
}
