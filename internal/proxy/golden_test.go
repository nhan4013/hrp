package proxy

import (
	"flag"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/nhan4013/hrp/internal/cassette"
	"github.com/nhan4013/hrp/internal/redact"
)

// update regenerates the golden files: go test ./internal/proxy -update
//
// A golden test guards the whole recorded format at once — field names, ordering,
// which headers survive, how bodies are stored. Unit tests check those one at a
// time and would not notice a change in how they fit together.
var update = flag.Bool("update", false, "update golden files")

const goldenCassette = "testdata/golden/record.yaml"

func TestGoldenCassette(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/charges":
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Set-Cookie", "session=should-not-be-recorded")
			w.Header().Set("X-Request-Id", "volatile-should-be-dropped")
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"id":"ch_123","status":"succeeded"}`))
		case "/v1/blob":
			w.Header().Set("Content-Type", "application/gzip")
			_, _ = w.Write([]byte{0x1f, 0x8b, 0x08, 0x00, 0xff, 0xfe})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer upstream.Close()

	path := filepath.Join(t.TempDir(), "c.yaml")
	store, err := cassette.Load(path, "golden", upstream.URL)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	redactor, err := redact.New(redact.Rules{
		JSONFields: []string{"card.number", "cvv"},
		Patterns:   []redact.Pattern{{Name: "digits19", Regex: `\b\d{13,19}\b`}},
	})
	if err != nil {
		t.Fatalf("redact.New: %v", err)
	}
	srv, err := New(Config{
		Listen: ":0", Upstream: upstream.URL, Mode: ModeRecord,
		Store: store, Redactor: redactor,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	front := httptest.NewServer(srv.http.Handler)
	defer front.Close()

	// A POST with secrets in headers and body, and a binary GET.
	req, err := http.NewRequest(http.MethodPost,
		front.URL+"/v1/charges?currency=VND&amount=1500000",
		strings.NewReader(`{"amount":1500000,"card":{"number":"4111111111111111","brand":"visa"},"cvv":"123"}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer a-token")
	req.Header.Set("X-Request-Id", "volatile-should-be-dropped")
	drain(t, front.Client(), req)

	blob, err := http.NewRequest(http.MethodGet, front.URL+"/v1/blob", nil)
	if err != nil {
		t.Fatal(err)
	}
	drain(t, front.Client(), blob)

	if err := store.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	got := normalizeCassette(t, raw, upstream.URL)
	compareGolden(t, goldenCassette, got)
}

// normalizeCassette blanks the fields that cannot repeat between runs: wall-clock
// timestamps, measured durations, and the random port httptest binds to.
func normalizeCassette(t *testing.T, raw []byte, upstreamURL string) []byte {
	t.Helper()

	var c cassette.Cassette
	if err := yaml.Unmarshal(raw, &c); err != nil {
		t.Fatalf("unmarshal cassette: %v", err)
	}
	c.RecordedAt = time.Time{}
	c.Upstream = strings.Replace(c.Upstream, upstreamURL, "http://upstream.test", 1)
	for i := range c.Interactions {
		c.Interactions[i].Meta.RecordedAt = time.Time{}
		c.Interactions[i].Response.DurationMS = 0
	}

	out, err := yaml.Marshal(&c)
	if err != nil {
		t.Fatalf("marshal cassette: %v", err)
	}
	return out
}

func compareGolden(t *testing.T, path string, got []byte) {
	t.Helper()

	if *update {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("updated %s", path)
		return
	}

	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden %s: %v\nrun: go test ./%s -update",
			path, err, filepath.Dir(filepath.Dir(path)))
	}
	if string(got) != string(want) {
		t.Errorf("%s is out of date.\n\n--- want ---\n%s\n--- got ---\n%s\n\n"+
			"If the change is intended, re-run with -update and review the diff.",
			path, want, got)
	}
}

// drain performs a request and discards the response. The client call lives
// inside the helper so the deferred Close is visible to the bodyclose linter.
func drain(t *testing.T, client *http.Client, req *http.Request) {
	t.Helper()
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", req.Method, req.URL.Path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if _, err := io.Copy(io.Discard, resp.Body); err != nil {
		t.Fatalf("drain body: %v", err)
	}
}
