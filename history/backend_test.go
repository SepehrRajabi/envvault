package history

import (
	"errors"
	"testing"
)

// fakeBackend is an in-memory Backend used to verify that the package-level
// Record/List/Clear helpers dispatch to whatever backend is active, without
// touching disk or the network.
type fakeBackend struct {
	events    []Event
	cleared   bool
	recordErr error
	listErr   error
	clearErr  error
}

func (f *fakeBackend) Record(e Event) error {
	if f.recordErr != nil {
		return f.recordErr
	}
	f.events = append(f.events, e)
	return nil
}

func (f *fakeBackend) List(limit int) ([]Event, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	if limit > 0 && limit < len(f.events) {
		return f.events[:limit], nil
	}
	return f.events, nil
}

func (f *fakeBackend) Clear() error {
	if f.clearErr != nil {
		return f.clearErr
	}
	f.cleared = true
	f.events = nil
	return nil
}

func withBackend(t *testing.T, b Backend) {
	t.Helper()
	prev := active
	SetBackend(b)
	t.Cleanup(func() { SetBackend(prev) })
}

func TestRecordDispatchesToActiveBackend(t *testing.T) {
	fake := &fakeBackend{}
	withBackend(t, fake)

	if err := Record("Lock", "file.env.vault", "aes256gcm-argon2id"); err != nil {
		t.Fatalf("Record: %v", err)
	}

	if len(fake.events) != 1 {
		t.Fatalf("expected 1 event recorded on active backend, got %d", len(fake.events))
	}
	e := fake.events[0]
	if e.Action != "Lock" || e.File != "file.env.vault" || e.Algorithm != "aes256gcm-argon2id" {
		t.Fatalf("unexpected event recorded: %+v", e)
	}
	if e.Timestamp.IsZero() {
		t.Fatal("expected Record to stamp a non-zero timestamp")
	}
}

func TestListDispatchesToActiveBackend(t *testing.T) {
	fake := &fakeBackend{events: []Event{{Action: "Lock"}, {Action: "Unlock"}}}
	withBackend(t, fake)

	events, err := List(0)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("expected 2 events from active backend, got %d", len(events))
	}
}

func TestClearDispatchesToActiveBackend(t *testing.T) {
	fake := &fakeBackend{events: []Event{{Action: "Lock"}}}
	withBackend(t, fake)

	if err := Clear(); err != nil {
		t.Fatalf("Clear: %v", err)
	}
	if !fake.cleared {
		t.Fatal("expected Clear to reach the active backend")
	}
}

func TestRecordPropagatesBackendError(t *testing.T) {
	wantErr := errors.New("boom")
	withBackend(t, &fakeBackend{recordErr: wantErr})

	if err := Record("Lock", "f", ""); !errors.Is(err, wantErr) {
		t.Fatalf("expected Record to propagate backend error, got %v", err)
	}
}

func TestSetBackendSwitchesActiveBackend(t *testing.T) {
	first := &fakeBackend{}
	second := &fakeBackend{}
	withBackend(t, first)

	_ = Record("Lock", "f", "")
	SetBackend(second)
	_ = Record("Unlock", "f", "")

	if len(first.events) != 1 {
		t.Fatalf("expected first backend to receive only the pre-switch event, got %d", len(first.events))
	}
	if len(second.events) != 1 {
		t.Fatalf("expected second backend to receive only the post-switch event, got %d", len(second.events))
	}
}
