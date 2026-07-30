package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/nhan4013/hrp/internal/cassette"
	"github.com/nhan4013/hrp/internal/matcher"
	"github.com/nhan4013/hrp/internal/mitm"
	"github.com/nhan4013/hrp/internal/redact"
)

var mitmRules = []string{"method", "host", "path", "query", "body"}

func newCA(t *testing.T) *mitm.CA {
	t.Helper()
	ca, err := mitm.GenerateCA()
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}
	return ca
}

func newStore(t *testing.T, path string) *cassette.Store {
	t.Helper()
	store, err := cassette.Load(path, "test", "")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return store
}

func newMatcher(t *testing.T) *matcher.Matcher {
	t.Helper()
	m, err := matcher.New(mitmRules)
	if err != nil {
		t.Fatalf("matcher.New: %v", err)
	}
	return m
}

// startMITM runs the proxy's handler behind a real server, and returns a client
// that proxies through it while trusting the CA — the whole point of MITM.
func startMITM(t *testing.T, cfg Config) (front *httptest.Server, client *http.Client) {
	t.Helper()
	if cfg.CA == nil {
		cfg.CA = newCA(t)
	}
	s, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	front = httptest.NewServer(s.http.Handler)
	t.Cleanup(front.Close)

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(cfg.CA.CertPEM()) {
		t.Fatal("AppendCertsFromPEM: CA PEM not accepted")
	}
	proxyURL, err := url.Parse(front.URL)
	if err != nil {
		t.Fatal(err)
	}
	tr := &http.Transport{
		Proxy:           http.ProxyURL(proxyURL),
		TLSClientConfig: &tls.Config{RootCAs: pool},
	}
	t.Cleanup(tr.CloseIdleConnections)
	return front, &http.Client{Transport: tr}
}

func tlsUpstream(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	upstream := httptest.NewTLSServer(handler)
	t.Cleanup(upstream.Close)
	return upstream
}

// exchange is what a request came back with, minus the body itself — returned
// separately so no *http.Response escapes its Close.
type exchange struct {
	status int
	replay string
}

func get(t *testing.T, client *http.Client, url string) (body string, ex exchange) {
	t.Helper()
	r, err := client.Get(url)
	if err != nil {
		t.Fatalf("Get %s: %v", url, err)
	}
	defer func() { _ = r.Body.Close() }()
	raw, _ := io.ReadAll(r.Body)
	return string(raw), exchange{status: r.StatusCode, replay: r.Header.Get("X-Hrp-Replay")}
}

func TestMITMRecordsHTTPSThroughConnect(t *testing.T) {
	var gotAuth string
	var gotBody []byte
	upstream := tlsUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"id":"ch_1","status":"succeeded"}`))
	})
	host := strings.TrimPrefix(upstream.URL, "https://")

	path := filepath.Join(t.TempDir(), "c.yaml")
	store := newStore(t, path)
	// Body redaction is configured, never default: the card number below must
	// land in the cassette as a placeholder.
	redactor, err := redact.New(redact.Rules{
		Patterns: []redact.Pattern{{Name: "card_number", Regex: `\b\d{13,19}\b`}},
	})
	if err != nil {
		t.Fatalf("redact.New: %v", err)
	}
	_, client := startMITM(t, Config{
		Listen:    ":0",
		Mode:      ModeRecord,
		Store:     store,
		Redactor:  redactor,
		Transport: upstream.Client().Transport,
	})

	req, err := http.NewRequest(http.MethodPost,
		"https://"+host+"/v1/charges?currency=VND",
		strings.NewReader(`{"amount":1500000,"card":"4111111111111111"}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer super-secret")
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Do through CONNECT tunnel: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	clientBody, _ := io.ReadAll(resp.Body)

	// Both legs of the tunnel stay intact: the upstream sees the real request,
	// the client sees the real response.
	if gotAuth != "Bearer super-secret" {
		t.Errorf("upstream Authorization = %q, want the real token", gotAuth)
	}
	if string(gotBody) != `{"amount":1500000,"card":"4111111111111111"}` {
		t.Errorf("upstream body = %q, want it forwarded intact", gotBody)
	}
	if resp.StatusCode != http.StatusCreated {
		t.Errorf("client status = %d, want 201", resp.StatusCode)
	}
	if string(clientBody) != `{"id":"ch_1","status":"succeeded"}` {
		t.Errorf("client body = %q", clientBody)
	}

	if store.Len() != 1 {
		t.Fatalf("store.Len = %d, want 1", store.Len())
	}
	recorded := store.Interactions()[0].Request
	if recorded.Scheme != "https" {
		t.Errorf("scheme = %q, want https", recorded.Scheme)
	}
	if recorded.Host != host {
		t.Errorf("host = %q, want %q", recorded.Host, host)
	}
	if recorded.Path != "/v1/charges" {
		t.Errorf("path = %q", recorded.Path)
	}
	if got := url.Values(recorded.Query).Get("currency"); got != "VND" {
		t.Errorf("query currency = %q", got)
	}

	// The file itself shows scheme and host; the card number stays out of it.
	if err := store.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	yaml := string(raw)
	for _, want := range []string{"scheme: https", "host: " + host, "path: /v1/charges", "status: 201", redact.Placeholder} {
		if !strings.Contains(yaml, want) {
			t.Errorf("cassette missing %q:\n%s", want, yaml)
		}
	}
	for _, secret := range []string{"super-secret", "4111111111111111"} {
		if strings.Contains(yaml, secret) {
			t.Errorf("cassette leaked %q:\n%s", secret, yaml)
		}
	}
}

func TestMITMReplayNeverLeavesTheMachine(t *testing.T) {
	upstream := tlsUpstream(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"rate":25000}`))
	})
	host := strings.TrimPrefix(upstream.URL, "https://")

	store := newStore(t, filepath.Join(t.TempDir(), "c.yaml"))
	_, client := startMITM(t, Config{
		Listen: ":0", Mode: ModeRecord, Store: store,
		Transport: upstream.Client().Transport,
	})
	if body, _ := get(t, client, "https://"+host+"/v1/rates?base=VND"); body != `{"rate":25000}` {
		t.Fatalf("record body = %q", body)
	}
	if store.Len() != 1 {
		t.Fatalf("recorded %d interactions, want 1", store.Len())
	}

	// Replay with the upstream gone: a hit proves the answer came off disk.
	upstream.Close()
	_, replay := startMITM(t, Config{
		Listen: ":0", Mode: ModeReplay, Store: store, Matcher: newMatcher(t),
	})

	body, ex := get(t, replay, "https://"+host+"/v1/rates?base=VND")
	if ex.replay != "hit" {
		t.Errorf("X-Hrp-Replay = %q, want hit", ex.replay)
	}
	if body != `{"rate":25000}` {
		t.Errorf("replayed body = %q", body)
	}

	_, miss := get(t, replay, "https://"+host+"/v1/rates?base=USD")
	if miss.status != 599 {
		t.Errorf("miss status = %d, want 599", miss.status)
	}
	if miss.replay != "miss" {
		t.Errorf("X-Hrp-Replay = %q, want miss", miss.replay)
	}
}

// Two upstreams answering the same path must be two different interactions:
// the host rule is what keeps a forward-proxy cassette from collapsing them.
func TestMITMDistinguishesUpstreamsByHost(t *testing.T) {
	handler := func(body string) http.HandlerFunc {
		return func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(body)) }
	}
	upA := tlsUpstream(t, handler(`{"from":"a"}`))
	upB := tlsUpstream(t, handler(`{"from":"b"}`))
	urlA := upA.URL + "/v1/ping"
	urlB := upB.URL + "/v1/ping"

	store := newStore(t, filepath.Join(t.TempDir(), "c.yaml"))
	_, recClient := startMITM(t, Config{
		Listen: ":0", Mode: ModeRecord, Store: store,
		// Both test upstreams share httptest's cert shape, and each client's
		// transport trusts its own — chain them by using a pool with both.
		Transport: bothUpstreamTransport(t, upA, upB),
	})
	if _, ex := get(t, recClient, urlA); ex.status != 200 {
		t.Fatalf("record A: status %d", ex.status)
	}
	if _, ex := get(t, recClient, urlB); ex.status != 200 {
		t.Fatalf("record B: status %d", ex.status)
	}
	if store.Len() != 2 {
		t.Fatalf("store.Len = %d, want 2 — one per host", store.Len())
	}

	_, replay := startMITM(t, Config{
		Listen: ":0", Mode: ModeReplay, Store: store, Matcher: newMatcher(t),
	})
	for u, want := range map[string]string{urlA: `{"from":"a"}`, urlB: `{"from":"b"}`} {
		body, ex := get(t, replay, u)
		if ex.replay != "hit" || body != want {
			t.Errorf("replay %s = (%q, %q), want (%q, hit)", u, body, ex.replay, want)
		}
	}
}

// bothUpstreamTransport trusts two httptest TLS servers at once.
func bothUpstreamTransport(t *testing.T, servers ...*httptest.Server) http.RoundTripper {
	t.Helper()
	pool := x509.NewCertPool()
	for _, s := range servers {
		pool.AddCert(s.Certificate())
	}
	return &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}
}

// Plain HTTP through a forward proxy never sends CONNECT: the absolute URL is
// on the request line itself.
func TestMITMRecordsPlainHTTPWithoutConnect(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("pong"))
	}))
	t.Cleanup(upstream.Close)

	store := newStore(t, filepath.Join(t.TempDir(), "c.yaml"))
	_, client := startMITM(t, Config{Listen: ":0", Mode: ModeRecord, Store: store})

	body, _ := get(t, client, upstream.URL+"/ping")
	if body != "pong" {
		t.Errorf("body = %q, want pong", body)
	}
	if store.Len() != 1 {
		t.Fatalf("store.Len = %d, want 1", store.Len())
	}
	recorded := store.Interactions()[0].Request
	if recorded.Scheme != "http" {
		t.Errorf("scheme = %q, want http", recorded.Scheme)
	}
	if recorded.Host != strings.TrimPrefix(upstream.URL, "http://") {
		t.Errorf("host = %q, want the upstream's", recorded.Host)
	}
}

// A request that arrives in origin-form was pointed at hrp as if hrp were the
// API. Say so, rather than matching it against nothing.
func TestMITMRejectsOriginForm(t *testing.T) {
	front, _ := startMITM(t, Config{Listen: ":0", Mode: ModePassthrough})

	conn, err := net.Dial("tcp", strings.TrimPrefix(front.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := fmt.Fprintf(conn, "GET /origin-form HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	raw, err := io.ReadAll(conn)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "400 Bad Request") {
		t.Errorf("origin-form got:\n%s", raw)
	}
	if !strings.Contains(string(raw), "forward proxy") {
		t.Errorf("error should point at HTTP_PROXY usage:\n%s", raw)
	}
}

// Concurrent tunnels share the CA's leaf cache and the store (go test -race).
func TestMITMConcurrentTunnelsAreRaceFree(t *testing.T) {
	upstream := tlsUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_, _ = w.Write(append([]byte(`{"echo":`), append(body, '}')...))
	})
	host := strings.TrimPrefix(upstream.URL, "https://")

	store := newStore(t, filepath.Join(t.TempDir(), "c.yaml"))
	_, client := startMITM(t, Config{
		Listen: ":0", Mode: ModeRecord, Store: store,
		Transport: upstream.Client().Transport,
	})

	const n = 20
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			resp, err := client.Post("https://"+host+"/v1/charges", "application/json",
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

func TestMITMAutoRecordsMissesAndReplaysHits(t *testing.T) {
	upstream := tlsUpstream(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"rate":25000}`))
	})
	host := strings.TrimPrefix(upstream.URL, "https://")

	store := newStore(t, filepath.Join(t.TempDir(), "c.yaml"))
	_, client := startMITM(t, Config{
		Listen: ":0", Mode: ModeAuto, Store: store, Matcher: newMatcher(t),
		Transport: upstream.Client().Transport,
	})

	body, ex := get(t, client, "https://"+host+"/v1/rates?base=VND")
	if body != `{"rate":25000}` || ex.replay != "" {
		t.Errorf("first call = (%q, replay %q), want a forwarded response", body, ex.replay)
	}
	body, ex = get(t, client, "https://"+host+"/v1/rates?base=VND")
	if body != `{"rate":25000}` || ex.replay != "hit" {
		t.Errorf("second call = (%q, replay %q), want a cassette hit", body, ex.replay)
	}
	if store.Len() != 1 {
		t.Errorf("store.Len = %d, want 1", store.Len())
	}
}
