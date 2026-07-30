package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/nhan4013/hrp/internal/cassette"
	"github.com/nhan4013/hrp/internal/matcher"
)

// autoFixture returns an auto-mode proxy plus a counter of how many requests
// actually reached the upstream.
func autoFixture(t *testing.T) (front *httptest.Server, store *cassette.Store, upstreamHits *atomic.Int64) {
	t.Helper()

	upstreamHits = &atomic.Int64{}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHits.Add(1)
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"path":"` + r.URL.Path + `","sent":` + quote(string(body)) + `}`))
	}))
	t.Cleanup(upstream.Close)

	store, err := cassette.Load(filepath.Join(t.TempDir(), "c.yaml"), "test", upstream.URL)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	m, err := matcher.New(matcher.DefaultRules)
	if err != nil {
		t.Fatalf("matcher.New: %v", err)
	}
	s, err := New(Config{
		Listen: ":0", Upstream: upstream.URL, Mode: ModeAuto, Store: store, Matcher: m,
	})
	if err != nil {
		t.Fatalf("New auto: %v", err)
	}
	front = httptest.NewServer(s.http.Handler)
	t.Cleanup(front.Close)
	return front, store, upstreamHits
}

// The point of auto mode: the first call goes out and is recorded, every repeat
// is served from the cassette without touching the network.
func TestAutoRecordsOnceThenReplays(t *testing.T) {
	front, store, hits := autoFixture(t)

	first := post(t, front, "/v1/charges", `{"amount":1}`)
	if first.status != http.StatusCreated {
		t.Fatalf("first status = %d, want 201\n%s", first.status, first.body)
	}
	if got := hits.Load(); got != 1 {
		t.Fatalf("upstream hits after first call = %d, want 1", got)
	}
	if store.Len() != 1 {
		t.Fatalf("store.Len = %d, want 1", store.Len())
	}

	for i := 0; i < 5; i++ {
		again := post(t, front, "/v1/charges", `{"amount":1}`)
		if again.status != http.StatusCreated {
			t.Errorf("repeat %d status = %d, want 201\n%s", i, again.status, again.body)
		}
		if again.body != first.body {
			t.Errorf("repeat %d body = %q, want %q", i, again.body, first.body)
		}
		if again.header.Get(replayHeader) != "hit" {
			t.Errorf("repeat %d %s = %q, want hit", i, replayHeader,
				again.header.Get(replayHeader))
		}
	}

	if got := hits.Load(); got != 1 {
		t.Errorf("upstream hits = %d, want 1: repeats must be served from the cassette", got)
	}
	if store.Len() != 1 {
		t.Errorf("store.Len = %d, want 1", store.Len())
	}
}

// A request that differs must not be answered from a near miss; it goes out and
// is recorded as its own interaction.
func TestAutoRecordsNewRequestsAlongsideOldOnes(t *testing.T) {
	front, store, hits := autoFixture(t)

	post(t, front, "/v1/charges", `{"amount":1}`)
	post(t, front, "/v1/charges", `{"amount":2}`)
	post(t, front, "/v1/refunds", `{"amount":1}`)

	if got := hits.Load(); got != 3 {
		t.Errorf("upstream hits = %d, want 3", got)
	}
	if store.Len() != 3 {
		t.Errorf("store.Len = %d, want 3", store.Len())
	}

	// All three must now replay without going out again.
	post(t, front, "/v1/charges", `{"amount":1}`)
	post(t, front, "/v1/charges", `{"amount":2}`)
	post(t, front, "/v1/refunds", `{"amount":1}`)
	if got := hits.Load(); got != 3 {
		t.Errorf("upstream hits after replays = %d, want 3", got)
	}
}

// Auto mode never returns 599: there is always an upstream to fall back on.
func TestAutoNeverReturns599(t *testing.T) {
	front, _, _ := autoFixture(t)

	got := post(t, front, "/v1/anything", `{"never":"recorded"}`)
	if got.status == statusNoMatch {
		t.Errorf("status = %d, want a real response: auto mode has an upstream", got.status)
	}
	if got.header.Get(replayHeader) == "miss" {
		t.Errorf("%s = miss, want the request forwarded instead", replayHeader)
	}
}

// The body is buffered by the replay lookup and must still reach the upstream
// intact when the request falls through to recording.
func TestAutoForwardsBodyIntactOnMiss(t *testing.T) {
	var got []byte
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	store, err := cassette.Load(filepath.Join(t.TempDir(), "c.yaml"), "test", upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	m, err := matcher.New(matcher.DefaultRules)
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(Config{
		Listen: ":0", Upstream: upstream.URL, Mode: ModeAuto, Store: store, Matcher: m,
	})
	if err != nil {
		t.Fatal(err)
	}
	front := httptest.NewServer(s.http.Handler)
	defer front.Close()

	want := `{"amount":1500000,"note":"` + strings.Repeat("x", 5000) + `"}`
	post(t, front, "/v1/charges", want)

	if string(got) != want {
		t.Errorf("upstream received %d bytes, want %d", len(got), len(want))
	}
	if store.Len() != 1 {
		t.Errorf("store.Len = %d, want 1", store.Len())
	}
}

// Concurrent identical misses may all go out, but dedup must leave one
// interaction, and the run must be race-free.
func TestAutoConcurrentIdenticalMisses(t *testing.T) {
	front, store, _ := autoFixture(t)

	const n = 30
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			if got := post(t, front, "/v1/charges", `{"amount":1}`); got.status != http.StatusCreated {
				t.Errorf("status = %d, want 201\n%s", got.status, got.body)
			}
		}()
	}
	wg.Wait()

	if store.Len() != 1 {
		t.Errorf("store.Len = %d, want 1 after dedup", store.Len())
	}
}

func TestAutoConfigValidation(t *testing.T) {
	m, err := matcher.New(matcher.DefaultRules)
	if err != nil {
		t.Fatal(err)
	}
	store, err := cassette.Load(filepath.Join(t.TempDir(), "c.yaml"), "x", "y")
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name string
		cfg  Config
	}{
		{"auto without store", Config{Mode: ModeAuto, Upstream: "http://v.com", Matcher: m}},
		{"auto without matcher", Config{Mode: ModeAuto, Upstream: "http://v.com", Store: store}},
		{"auto without upstream", Config{Mode: ModeAuto, Store: store, Matcher: m}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := New(tt.cfg); err == nil {
				t.Errorf("New(%+v) = nil error, want error", tt.cfg)
			}
		})
	}
}
