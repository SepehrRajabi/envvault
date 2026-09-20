package history

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// HTTPBackend forwards history events to a remote collector over HTTP.
// Record issues POST /events, List issues GET /events?limit=N, and Clear
// issues DELETE /events against the configured endpoint.
type HTTPBackend struct {
	Endpoint string
	Token    string
	Client   *http.Client
}

// NewHTTPBackend builds an HTTPBackend for the given endpoint. token is
// sent as a Bearer token when non-empty.
func NewHTTPBackend(endpoint, token string) *HTTPBackend {
	return &HTTPBackend{
		Endpoint: strings.TrimRight(endpoint, "/"),
		Token:    token,
		Client:   &http.Client{Timeout: 5 * time.Second},
	}
}

func (b *HTTPBackend) Record(e Event) error {
	body, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("encoding history event: %w", err)
	}

	resp, err := b.do(http.MethodPost, "/events", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("recording remote history event: %w", err)
	}
	defer resp.Body.Close()

	return checkStatus(resp)
}

func (b *HTTPBackend) List(limit int) ([]Event, error) {
	path := "/events"
	if limit > 0 {
		path = fmt.Sprintf("/events?limit=%d", limit)
	}

	resp, err := b.do(http.MethodGet, path, nil)
	if err != nil {
		return nil, fmt.Errorf("listing remote history events: %w", err)
	}
	defer resp.Body.Close()

	if err := checkStatus(resp); err != nil {
		return nil, err
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading remote history response: %w", err)
	}

	var events []Event
	if err := json.Unmarshal(data, &events); err != nil {
		return nil, fmt.Errorf("parsing remote history response: %w", err)
	}

	return events, nil
}

func (b *HTTPBackend) Clear() error {
	resp, err := b.do(http.MethodDelete, "/events", nil)
	if err != nil {
		return fmt.Errorf("clearing remote history: %w", err)
	}
	defer resp.Body.Close()

	return checkStatus(resp)
}

// do issues an HTTP request. It deliberately does not wrap the request in a
// context.WithTimeout: the caller reads the response body (io.ReadAll in
// List) after do returns, and a deferred cancel here would fire before that
// read completes, intermittently failing it with "context canceled" for any
// response not already fully buffered. b.Client.Timeout already bounds the
// entire round trip, including the body read, so it's sufficient on its own.
func (b *HTTPBackend) do(method, path string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequest(method, b.Endpoint+path, body)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if b.Token != "" {
		req.Header.Set("Authorization", "Bearer "+b.Token)
	}

	return b.Client.Do(req)
}

func checkStatus(resp *http.Response) error {
	if resp.StatusCode >= 300 {
		return fmt.Errorf("remote history server returned %s", resp.Status)
	}
	return nil
}
