package history

import (
	"testing"
	"time"
)

func TestLocalBackendListOnEmptyHistoryReturnsNoError(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	b := NewLocalBackend()

	events, err := b.List(0)
	if err != nil {
		t.Fatalf("List on empty history: %v", err)
	}
	if len(events) != 0 {
		t.Fatalf("expected no events, got %d", len(events))
	}
}

func TestLocalBackendRecordAndList(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	b := NewLocalBackend()

	now := time.Now()
	if err := b.Record(Event{Timestamp: now, Action: "Lock", File: "a.env.vault", Algorithm: "aes256gcm-argon2id"}); err != nil {
		t.Fatalf("Record: %v", err)
	}
	if err := b.Record(Event{Timestamp: now.Add(time.Second), Action: "Unlock", File: "a.env.vault"}); err != nil {
		t.Fatalf("Record: %v", err)
	}

	events, err := b.List(0)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("expected 2 events, got %d", len(events))
	}
	// Newest first.
	if events[0].Action != "Unlock" || events[1].Action != "Lock" {
		t.Fatalf("expected newest-first ordering, got %+v", events)
	}
}

func TestLocalBackendListRespectsLimit(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	b := NewLocalBackend()

	for range 5 {
		if err := b.Record(Event{Action: "Lock", File: "a.env.vault"}); err != nil {
			t.Fatalf("Record: %v", err)
		}
	}

	events, err := b.List(2)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("expected List(2) to return 2 events, got %d", len(events))
	}
}

func TestLocalBackendClearRemovesEvents(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	b := NewLocalBackend()

	if err := b.Record(Event{Action: "Lock", File: "a.env.vault"}); err != nil {
		t.Fatalf("Record: %v", err)
	}
	if err := b.Clear(); err != nil {
		t.Fatalf("Clear: %v", err)
	}

	events, err := b.List(0)
	if err != nil {
		t.Fatalf("List after clear: %v", err)
	}
	if len(events) != 0 {
		t.Fatalf("expected no events after clear, got %d", len(events))
	}
}

func TestLocalBackendClearOnMissingFileIsNotAnError(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	b := NewLocalBackend()

	if err := b.Clear(); err != nil {
		t.Fatalf("Clear with no history file yet: %v", err)
	}
}

func TestLocalBackendCapsStoredEvents(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	b := NewLocalBackend()

	total := maxLocalEvents + 5
	for i := range total {
		if err := b.Record(Event{Action: "Lock", File: "a.env.vault"}); err != nil {
			t.Fatalf("Record %d: %v", i, err)
		}
	}

	events, err := b.List(0)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(events) != maxLocalEvents {
		t.Fatalf("expected history capped at %d events, got %d", maxLocalEvents, len(events))
	}
}
