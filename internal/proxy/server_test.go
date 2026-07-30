package proxy

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestNewRejectsBadUpstream(t *testing.T) {
	tests := []struct {
		name     string
		upstream string
	}{
		{"empty", ""},
		{"no scheme", "sandbox.vendor.com"},
		{"no host", "https://"},
		{"unsupported scheme", "ftp://vendor.com"},
		{"control char", "http://vendor.com/\x7f"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := New(Config{Listen: ":8080", Upstream: tt.upstream}); err == nil {
				t.Errorf("New(%q) = nil error, want error", tt.upstream)
			}
		})
	}
}

func TestNewAcceptsValidUpstream(t *testing.T) {
	for _, upstream := range []string{"http://vendor.com", "https://vendor.com/v1"} {
		if _, err := New(Config{Listen: ":8080", Upstream: upstream}); err != nil {
			t.Errorf("New(%q) = %v, want nil", upstream, err)
		}
	}
}

// The proxy must forward method, path, query, body and headers unchanged,
// and hand the upstream response back verbatim.
func TestForwardsRequestAndResponse(t *testing.T) {
	var (
		gotMethod string
		gotPath   string
		gotQuery  string
		gotHeader string
		gotBody   []byte
	)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath = r.Method, r.URL.Path
		gotQuery = r.URL.RawQuery
		gotHeader = r.Header.Get("X-Api-Key")
		gotBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"id":"ch_123"}`))
	}))
	defer upstream.Close()

	s, err := New(Config{Listen: ":0", Upstream: upstream.URL})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	front := httptest.NewServer(s.http.Handler)
	defer front.Close()

	req, err := http.NewRequest(http.MethodPost,
		front.URL+"/v1/charges?currency=VND", strings.NewReader(`{"amount":1500000}`))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("X-Api-Key", "secret")

	resp, err := front.Client().Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)

	if gotMethod != http.MethodPost {
		t.Errorf("upstream method = %q, want POST", gotMethod)
	}
	if gotPath != "/v1/charges" {
		t.Errorf("upstream path = %q, want /v1/charges", gotPath)
	}
	if gotQuery != "currency=VND" {
		t.Errorf("upstream query = %q, want currency=VND", gotQuery)
	}
	if gotHeader != "secret" {
		t.Errorf("upstream X-Api-Key = %q, want secret", gotHeader)
	}
	if string(gotBody) != `{"amount":1500000}` {
		t.Errorf("upstream body = %q, want {\"amount\":1500000}", gotBody)
	}
	if resp.StatusCode != http.StatusCreated {
		t.Errorf("status = %d, want 201", resp.StatusCode)
	}
	if got := resp.Header.Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", got)
	}
	if string(body) != `{"id":"ch_123"}` {
		t.Errorf("body = %q, want {\"id\":\"ch_123\"}", body)
	}
}

// A dead upstream must surface as 502, not a hung request or a panic.
func TestUnreachableUpstreamReturns502(t *testing.T) {
	dead := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	deadURL := dead.URL
	dead.Close() // nothing is listening on deadURL any more

	s, err := New(Config{Listen: ":0", Upstream: deadURL})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	front := httptest.NewServer(s.http.Handler)
	defer front.Close()

	resp, err := front.Client().Get(front.URL + "/get")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("status = %d, want 502", resp.StatusCode)
	}
}

// Cancelling the context must make Run return cleanly — later phases flush the
// cassette right after this returns, so a hang or an error here loses data.
func TestRunShutsDownOnContextCancel(t *testing.T) {
	s, err := New(Config{Listen: "127.0.0.1:0", Upstream: "http://vendor.invalid"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()
	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Run = %v, want nil", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after context cancel")
	}
}

// Run must report a bind failure instead of silently serving nothing.
func TestRunReportsBindFailure(t *testing.T) {
	busy := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer busy.Close()

	s, err := New(Config{Listen: busy.Listener.Addr().String(), Upstream: "http://vendor.invalid"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := s.Run(ctx); err == nil {
		t.Error("Run = nil, want bind error")
	}
}
