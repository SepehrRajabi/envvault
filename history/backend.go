// Package history records and retrieves the audit log of vault operations
// (lock, unlock, edit, rotate, ...) through a pluggable Backend: a local
// JSON file by default (see NewLocalBackend), or an HTTP collector (see
// NewHTTPBackend).
package history

import (
	"sync"
	"time"
)

// Event is a single recorded vault operation.
type Event struct {
	Timestamp time.Time `json:"timestamp"`
	Action    string    `json:"action"`
	File      string    `json:"file"`
	Algorithm string    `json:"algorithm,omitempty"`
}

// Backend persists and retrieves history events. The default backend keeps
// events in a local JSON file; alternate implementations (e.g. HTTPBackend)
// can forward events to a remote collector instead.
type Backend interface {
	Record(Event) error
	List(limit int) ([]Event, error)
	Clear() error
}

var (
	mu     sync.RWMutex
	active Backend = NewLocalBackend()
)

// SetBackend replaces the backend used by the package-level Record, List,
// and Clear functions.
func SetBackend(b Backend) {
	mu.Lock()
	defer mu.Unlock()
	active = b
}

func current() Backend {
	mu.RLock()
	defer mu.RUnlock()
	return active
}

// Record adds a new event to the history log via the active backend.
func Record(action, file, algorithm string) error {
	return current().Record(Event{
		Timestamp: time.Now(),
		Action:    action,
		File:      file,
		Algorithm: algorithm,
	})
}

// List returns the most recent `limit` events from the active backend.
func List(limit int) ([]Event, error) {
	return current().List(limit)
}

// Clear removes all events from the active backend.
func Clear() error {
	return current().Clear()
}
