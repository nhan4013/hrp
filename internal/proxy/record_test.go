package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/nhan4013/hrp/internal/cassette"
	"github.com/nhan4013/hrp/internal/redact"
)

// recordFixture spins up an echo upstream and a recording proxy in front of it.
func recordFixture(t *testing.T, upstreamHandler http.HandlerFunc) (front *httptest.Server, store *cassette.Store, path string) {
	t.Helper()

	upstream := httptest.NewServer(upstreamHandler)
	t.Cleanup(upstream.Close)

	path = filepath.Join(t.TempDir(), "c.yaml")
	store, err := cassette.Load(path, "test", upstream.URL)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	s, err := New(Config{Listen: ":0", Upstream: upstream.URL, Mode: ModeRecord, Store: store})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	front = httptest.NewServer(s.http.Handler)
	t.Cleanup(front.Close)
	return front, store, path
}

func echoHandler(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Set-Cookie", "session=abc123")
	w.WriteHeader(http.StatusCreated)
	_, _ = w.Write(append([]byte(`{"echo":`), append(body, '}')...))
}

func TestRecordsInteractionAndForwardsIntact(t *testing.T) {
	var gotAuth string
	var gotBody []byte
	front, store, path := recordFixture(t, func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Set-Cookie", "session=abc123")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"id":"ch_1"}`))
	})

	req, err := http.NewRequest(http.MethodPost,
		front.URL+"/v1/charges?currency=VND", strings.NewReader(`{"amount":1500000}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer super-secret")
	req.Header.Set("Content-Type", "application/json")

	resp, err := front.Client().Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	clientBody, _ := io.ReadAll(resp.Body)

	// The upstream must see the real, unredacted request.
	if gotAuth != "Bearer super-secret" {
		t.Errorf("upstream Authorization = %q, want the real token", gotAuth)
	}
	if string(gotBody) != `{"amount":1500000}` {
		t.Errorf("upstream body = %q, want it forwarded intact", gotBody)
	}
	// The client must see the real, unredacted response.
	if got := resp.Header.Get("Set-Cookie"); got != "session=abc123" {
		t.Errorf("client Set-Cookie = %q, want the real cookie", got)
	}
	if string(clientBody) != `{"id":"ch_1"}` {
		t.Errorf("client body = %q, want {\"id\":\"ch_1\"}", clientBody)
	}

	// The cassette must hold the interaction, with secrets removed.
	if store.Len() != 1 {
		t.Fatalf("store.Len = %d, want 1", store.Len())
	}
	if err := store.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	yaml := string(raw)

	for _, secret := range []string{"super-secret", "session=abc123"} {
		if strings.Contains(yaml, secret) {
			t.Errorf("cassette leaked %q:\n%s", secret, yaml)
		}
	}
	for _, want := range []string{
		redact.Placeholder,
		"method: POST",
		"path: /v1/charges",
		"currency",
		`{"amount":1500000}`,
		`{"id":"ch_1"}`,
		"status: 201",
	} {
		if !strings.Contains(yaml, want) {
			t.Errorf("cassette missing %q:\n%s", want, yaml)
		}
	}
}

// Replaying the same traffic twice must not duplicate interactions.
func TestRecordingSameRequestTwiceIsIdempotent(t *testing.T) {
	front, store, _ := recordFixture(t, echoHandler)

	for i := 0; i < 3; i++ {
		resp, err := front.Client().Post(front.URL+"/v1/charges", "application/json",
			strings.NewReader(`{"amount":1}`))
		if err != nil {
			t.Fatalf("post %d: %v", i, err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}
	if store.Len() != 1 {
		t.Errorf("store.Len = %d, want 1", store.Len())
	}
}

func TestDifferentRequestsRecordSeparately(t *testing.T) {
	front, store, _ := recordFixture(t, echoHandler)

	for _, body := range []string{`{"amount":1}`, `{"amount":2}`} {
		resp, err := front.Client().Post(front.URL+"/v1/charges", "application/json",
			strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}
	if store.Len() != 2 {
		t.Errorf("store.Len = %d, want 2", store.Len())
	}
}

// A body over the cap must still be relayed byte for byte. Recording it is
// optional; corrupting it is not.
func TestOversizedBodyIsForwardedButNotRecorded(t *testing.T) {
	var received int
	front, store, _ := recordFixture(t, func(w http.ResponseWriter, r *http.Request) {
		n, err := io.Copy(io.Discard, r.Body)
		if err != nil {
			t.Errorf("upstream read: %v", err)
		}
		received = int(n)
		w.WriteHeader(http.StatusOK)
	})

	size := cassette.MaxBodySize + 1024
	resp, err := front.Client().Post(front.URL+"/upload", "application/octet-stream",
		io.LimitReader(zeros{}, int64(size)))
	if err != nil {
		t.Fatalf("Post: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()

	if received != size {
		t.Errorf("upstream received %d bytes, want %d", received, size)
	}
	if store.Len() != 0 {
		t.Errorf("store.Len = %d, want 0 for an oversized body", store.Len())
	}
}

// A binary response must survive the cassette: base64 in, same bytes out.
func TestBinaryResponseIsRecordedAsBase64(t *testing.T) {
	want := []byte{0x1f, 0x8b, 0x08, 0x00, 0xff, 0xfe}
	front, store, _ := recordFixture(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/gzip")
		_, _ = w.Write(want)
	})

	resp, err := front.Client().Get(front.URL + "/blob")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()

	if store.Len() != 1 {
		t.Fatalf("store.Len = %d, want 1", store.Len())
	}
	res := store.Interactions()[0].Response
	if res.BodyEncoding != cassette.EncodingBase64 {
		t.Errorf("body_encoding = %q, want %q", res.BodyEncoding, cassette.EncodingBase64)
	}
	back, err := cassette.DecodeBody(res.Body, res.BodyEncoding)
	if err != nil {
		t.Fatalf("DecodeBody: %v", err)
	}
	if string(back) != string(want) {
		t.Errorf("decoded body = %x, want %x", back, want)
	}
}

// Concurrent traffic through a recording proxy must be race-free (go test -race).
func TestConcurrentRequestsAreRecorded(t *testing.T) {
	front, store, _ := recordFixture(t, echoHandler)

	const n = 50
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			resp, err := front.Client().Post(front.URL+"/v1/charges", "application/json",
				strings.NewReader(`{"amount":`+strconv.Itoa(i)+`}`))
			if err != nil {
				t.Errorf("post %d: %v", i, err)
				return
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
		}(i)
	}
	wg.Wait()

	if store.Len() != n {
		t.Errorf("store.Len = %d, want %d", store.Len(), n)
	}
}

func TestNilStoreRecordsNothing(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(echoHandler))
	defer upstream.Close()

	s, err := New(Config{Listen: ":0", Upstream: upstream.URL})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	front := httptest.NewServer(s.http.Handler)
	defer front.Close()

	resp, err := front.Client().Get(front.URL + "/get")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Errorf("status = %d, want 201", resp.StatusCode)
	}
}

type zeros struct{}

func (zeros) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 'x'
	}
	return len(p), nil
}
