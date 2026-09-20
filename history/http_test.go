package history

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestHTTPBackendRecordPostsEvent(t *testing.T) {
	var gotMethod, gotPath, gotAuth, gotContentType string
	var gotEvent Event

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		gotContentType = r.Header.Get("Content-Type")
		if err := json.NewDecoder(r.Body).Decode(&gotEvent); err != nil {
			t.Errorf("decoding request body: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	b := NewHTTPBackend(srv.URL, "s3cr3t")
	want := Event{Timestamp: time.Now(), Action: "Lock", File: "a.env.vault", Algorithm: "aes256gcm-argon2id"}
	if err := b.Record(want); err != nil {
		t.Fatalf("Record: %v", err)
	}

	if gotMethod != http.MethodPost {
		t.Errorf("expected POST, got %s", gotMethod)
	}
	if gotPath != "/events" {
		t.Errorf("expected path /events, got %s", gotPath)
	}
	if gotAuth != "Bearer s3cr3t" {
		t.Errorf("expected Authorization header, got %q", gotAuth)
	}
	if gotContentType != "application/json" {
		t.Errorf("expected JSON content type, got %q", gotContentType)
	}
	if gotEvent.Action != want.Action || gotEvent.File != want.File || gotEvent.Algorithm != want.Algorithm {
		t.Errorf("unexpected event sent: %+v", gotEvent)
	}
}

func TestHTTPBackendRecordWithoutTokenOmitsAuthHeader(t *testing.T) {
	var authSet bool

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, authSet = r.Header["Authorization"]
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	b := NewHTTPBackend(srv.URL, "")
	if err := b.Record(Event{Action: "Lock"}); err != nil {
		t.Fatalf("Record: %v", err)
	}

	if authSet {
		t.Error("expected no Authorization header when token is empty")
	}
}

func TestHTTPBackendRecordErrorsOnServerFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	b := NewHTTPBackend(srv.URL, "")
	if err := b.Record(Event{Action: "Lock"}); err == nil {
		t.Fatal("expected Record to fail when the server returns 500")
	}
}

func TestHTTPBackendListSendsLimitAndParsesResponse(t *testing.T) {
	var gotPath, gotQuery string

	want := []Event{
		{Action: "Unlock", File: "a.env.vault"},
		{Action: "Lock", File: "a.env.vault"},
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotQuery = r.URL.RawQuery
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(want)
	}))
	defer srv.Close()

	b := NewHTTPBackend(srv.URL, "")
	got, err := b.List(5)
	if err != nil {
		t.Fatalf("List: %v", err)
	}

	if gotPath != "/events" {
		t.Errorf("expected path /events, got %s", gotPath)
	}
	if gotQuery != "limit=5" {
		t.Errorf("expected query limit=5, got %q", gotQuery)
	}
	if len(got) != len(want) {
		t.Fatalf("expected %d events, got %d", len(want), len(got))
	}
	for i := range want {
		if got[i].Action != want[i].Action || got[i].File != want[i].File {
			t.Errorf("event %d mismatch: got %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestHTTPBackendListWithoutLimitOmitsQueryParam(t *testing.T) {
	var gotQuery string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode([]Event{})
	}))
	defer srv.Close()

	b := NewHTTPBackend(srv.URL, "")
	if _, err := b.List(0); err != nil {
		t.Fatalf("List: %v", err)
	}

	if gotQuery != "" {
		t.Errorf("expected no query string when limit is 0, got %q", gotQuery)
	}
}

func TestHTTPBackendListErrorsOnServerFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	b := NewHTTPBackend(srv.URL, "")
	if _, err := b.List(0); err == nil {
		t.Fatal("expected List to fail when the server returns 401")
	}
}

func TestHTTPBackendClearSendsDelete(t *testing.T) {
	var gotMethod, gotPath string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	b := NewHTTPBackend(srv.URL, "")
	if err := b.Clear(); err != nil {
		t.Fatalf("Clear: %v", err)
	}

	if gotMethod != http.MethodDelete {
		t.Errorf("expected DELETE, got %s", gotMethod)
	}
	if gotPath != "/events" {
		t.Errorf("expected path /events, got %s", gotPath)
	}
}

// TestHTTPBackendListDoesNotCancelBeforeBodyIsRead guards against a
// regression where do() wrapped requests in a context.WithTimeout and
// deferred its cancel, which fired as soon as do() returned — before List's
// io.ReadAll ran. Any response not already fully buffered by the transport
// then failed with "context canceled". Simulate that by trickling the
// response body across two writes with a delay in between.
func TestHTTPBackendListDoesNotCancelBeforeBodyIsRead(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		flusher, ok := w.(http.Flusher)
		if !ok {
			t.Fatal("ResponseWriter does not support flushing")
		}
		w.Write([]byte("["))
		flusher.Flush()
		time.Sleep(50 * time.Millisecond)
		w.Write([]byte(`{"action":"Lock"}]`))
	}))
	defer srv.Close()

	b := NewHTTPBackend(srv.URL, "")
	events, err := b.List(0)
	if err != nil {
		if strings.Contains(err.Error(), "context canceled") {
			t.Fatalf("body read was canceled before completing: %v", err)
		}
		t.Fatalf("unexpected error: %v", err)
	}
	if len(events) != 1 || events[0].Action != "Lock" {
		t.Fatalf("unexpected events: %+v", events)
	}
}

func TestNewHTTPBackendTrimsTrailingSlash(t *testing.T) {
	b := NewHTTPBackend("https://history.example.com/", "")
	if b.Endpoint != "https://history.example.com" {
		t.Fatalf("expected trailing slash to be trimmed, got %q", b.Endpoint)
	}
}
