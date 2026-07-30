package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/nhan4013/hrp/internal/cassette"
	"github.com/nhan4013/hrp/internal/matcher"
)

// recordThenReplay records traffic through a live upstream, shuts the upstream
// down, and returns a replay-only front end. Killing the upstream is the point:
// it proves replay never reaches the network.
func recordThenReplay(t *testing.T, record func(front *httptest.Server)) (*httptest.Server, *cassette.Store) {
	t.Helper()

	path := filepath.Join(t.TempDir(), "c.yaml")
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Vendor-Trace", "abc")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"path":"` + r.URL.Path + `","sent":` + quote(string(body)) + `}`))
	}))

	recStore, err := cassette.Load(path, "test", upstream.URL)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	recSrv, err := New(Config{Listen: ":0", Upstream: upstream.URL, Mode: ModeRecord, Store: recStore})
	if err != nil {
		t.Fatalf("New record: %v", err)
	}
	recFront := httptest.NewServer(recSrv.http.Handler)

	record(recFront)

	recFront.Close()
	upstream.Close() // from here on, any network attempt must fail
	if err := recStore.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}

	replayStore, err := cassette.Load(path, "", "")
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	m, err := matcher.New(matcher.DefaultRules)
	if err != nil {
		t.Fatalf("matcher.New: %v", err)
	}
	replaySrv, err := New(Config{Listen: ":0", Mode: ModeReplay, Store: replayStore, Matcher: m})
	if err != nil {
		t.Fatalf("New replay: %v", err)
	}
	front := httptest.NewServer(replaySrv.http.Handler)
	t.Cleanup(front.Close)
	return front, replayStore
}

func quote(s string) string {
	if s == "" {
		return `""`
	}
	return `"` + strings.ReplaceAll(s, `"`, `\"`) + `"`
}

// reply is the part of a response the tests assert on. Returning a value rather
// than *http.Response keeps the body closed inside the helper.
type reply struct {
	status int
	header http.Header
	body   string
}

func post(t *testing.T, srv *httptest.Server, path, body string) reply {
	t.Helper()
	resp, err := srv.Client().Post(srv.URL+path, "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	out, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return reply{status: resp.StatusCode, header: resp.Header, body: string(out)}
}

// The headline promise: pull the network out and the app still gets its answers.
func TestReplayServesFromCassetteWithNoNetwork(t *testing.T) {
	front, store := recordThenReplay(t, func(rec *httptest.Server) {
		post(t, rec, "/v1/charges", `{"amount":1500000}`)
		post(t, rec, "/v1/refunds", `{"amount":500}`)
	})

	got := post(t, front, "/v1/charges", `{"amount":1500000}`)
	if got.status != http.StatusCreated {
		t.Errorf("status = %d, want 201\n%s", got.status, got.body)
	}
	if got.header.Get(replayHeader) != "hit" {
		t.Errorf("%s = %q, want hit", replayHeader, got.header.Get(replayHeader))
	}
	if want := `"path":"/v1/charges"`; !strings.Contains(got.body, want) {
		t.Errorf("body = %q, want it to contain %q", got.body, want)
	}
	if ct := got.header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	if trace := got.header.Get("X-Vendor-Trace"); trace != "abc" {
		t.Errorf("X-Vendor-Trace = %q, want the recorded value", trace)
	}

	if got := store.Interactions()[0].Meta.HitCount; got != 1 {
		t.Errorf("hit_count = %d, want 1", got)
	}
}

// JSON key order differs between HTTP clients and languages; it must not decide
// a match.
func TestReplayMatchesRegardlessOfJSONKeyOrder(t *testing.T) {
	front, _ := recordThenReplay(t, func(rec *httptest.Server) {
		post(t, rec, "/v1/charges", `{"amount":1,"currency":"VND"}`)
	})

	got := post(t, front, "/v1/charges", `{"currency":"VND","amount":1}`)
	if got.status != http.StatusCreated {
		t.Errorf("status = %d, want 201\n%s", got.status, got.body)
	}
}

// A miss must return 599 with a report that names the real difference.
func TestReplayMissReturns599WithDiff(t *testing.T) {
	front, _ := recordThenReplay(t, func(rec *httptest.Server) {
		post(t, rec, "/v1/charges", `{"amount":1500000}`)
	})

	got := post(t, front, "/v1/charges", `{"amount":2000000}`)
	if got.status != statusNoMatch {
		t.Errorf("status = %d, want %d", got.status, statusNoMatch)
	}
	if got.header.Get(replayHeader) != "miss" {
		t.Errorf("%s = %q, want miss", replayHeader, got.header.Get(replayHeader))
	}
	for _, want := range []string{
		"POST /v1/charges",
		"Closest candidate:",
		"Differs on: body",
		"amount: recorded 1500000, incoming 2000000",
	} {
		if !strings.Contains(got.body, want) {
			t.Errorf("miss report missing %q:\n%s", want, got.body)
		}
	}
}

func TestReplayMissOnUnknownPathNamesClosestCandidate(t *testing.T) {
	front, _ := recordThenReplay(t, func(rec *httptest.Server) {
		post(t, rec, "/v1/charges", `{"amount":1}`)
	})

	got := post(t, front, "/v1/unknown", `{"amount":1}`)
	if got.status != statusNoMatch {
		t.Errorf("status = %d, want %d", got.status, statusNoMatch)
	}
	if !strings.Contains(got.body, "Differs on: path") {
		t.Errorf("miss report should blame the path:\n%s", got.body)
	}
}

// Replaying must never rewrite the cassette: a passing test suite has to leave a
// clean working tree.
func TestReplayLeavesCassetteUntouched(t *testing.T) {
	path := filepath.Join(t.TempDir(), "c.yaml")
	store, err := cassette.Load(path, "test", "http://vendor.invalid")
	if err != nil {
		t.Fatal(err)
	}
	store.Append(cassette.Interaction{
		ID:       "abc",
		Request:  cassette.Request{Method: http.MethodGet, Path: "/ping"},
		Response: cassette.Response{Status: 200, Body: "pong"},
	})
	if err := store.Flush(); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	m, err := matcher.New(matcher.DefaultRules)
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(Config{Listen: ":0", Mode: ModeReplay, Store: store, Matcher: m})
	if err != nil {
		t.Fatal(err)
	}
	front := httptest.NewServer(srv.http.Handler)
	defer front.Close()

	for i := 0; i < 5; i++ {
		resp, err := front.Client().Get(front.URL + "/ping")
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}
	if err := store.Flush(); err != nil {
		t.Fatalf("Flush after replay: %v", err)
	}

	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Error("replay rewrote the cassette; hit counts must stay in memory")
	}
	if got := store.Interactions()[0].Meta.HitCount; got != 5 {
		t.Errorf("in-memory hit_count = %d, want 5", got)
	}
}

func TestReplayRestoresBinaryBody(t *testing.T) {
	path := filepath.Join(t.TempDir(), "c.yaml")
	store, err := cassette.Load(path, "test", "")
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{0x1f, 0x8b, 0x08, 0x00, 0xff, 0xfe}
	body, enc := "H4sIAP/+", cassette.EncodingBase64
	store.Append(cassette.Interaction{
		ID:       "bin",
		Request:  cassette.Request{Method: http.MethodGet, Path: "/blob"},
		Response: cassette.Response{Status: 200, Body: body, BodyEncoding: enc},
	})

	m, err := matcher.New(matcher.DefaultRules)
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(Config{Listen: ":0", Mode: ModeReplay, Store: store, Matcher: m})
	if err != nil {
		t.Fatal(err)
	}
	front := httptest.NewServer(srv.http.Handler)
	defer front.Close()

	resp, err := front.Client().Get(front.URL + "/blob")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	got, _ := io.ReadAll(resp.Body)
	if string(got) != string(want) {
		t.Errorf("replayed body = %x, want %x", got, want)
	}
}

func TestReplayConcurrentHits(t *testing.T) {
	front, store := recordThenReplay(t, func(rec *httptest.Server) {
		post(t, rec, "/v1/charges", `{"amount":1}`)
	})

	const n = 50
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			got := post(t, front, "/v1/charges", `{"amount":1}`)
			if got.status != http.StatusCreated {
				t.Errorf("status = %d, want 201\n%s", got.status, got.body)
			}
		}()
	}
	wg.Wait()

	if got := store.Interactions()[0].Meta.HitCount; got != n {
		t.Errorf("hit_count = %d, want %d", got, n)
	}
}

func TestConfigValidation(t *testing.T) {
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
		{"replay without store", Config{Mode: ModeReplay, Matcher: m}},
		{"replay without matcher", Config{Mode: ModeReplay, Store: store}},
		{"record without store", Config{Mode: ModeRecord, Upstream: "http://v.com"}},
		{"record without upstream", Config{Mode: ModeRecord, Store: store}},
		{"passthrough without upstream", Config{Mode: ModePassthrough}},
		{"unknown mode", Config{Mode: Mode("rewind"), Upstream: "http://v.com"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := New(tt.cfg); err == nil {
				t.Errorf("New(%+v) = nil error, want error", tt.cfg)
			}
		})
	}
}

// Replay must not need an upstream: the whole point is that the vendor is gone.
func TestReplayNeedsNoUpstream(t *testing.T) {
	store, err := cassette.Load(filepath.Join(t.TempDir(), "c.yaml"), "x", "y")
	if err != nil {
		t.Fatal(err)
	}
	m, err := matcher.New(matcher.DefaultRules)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := New(Config{Listen: ":0", Mode: ModeReplay, Store: store, Matcher: m}); err != nil {
		t.Errorf("New replay without upstream = %v, want nil", err)
	}
}
