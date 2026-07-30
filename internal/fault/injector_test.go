package fault

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func okHandler(reached *atomic.Int64) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached.Add(1)
		w.WriteHeader(http.StatusOK)
	})
}

func TestNewRejectsBadConfig(t *testing.T) {
	tests := []struct {
		name string
		cfg  Config
	}{
		{"negative latency", Config{Latency: -time.Second}},
		{"error rate above 1", Config{ErrorRate: 1.5}},
		{"error rate below 0", Config{ErrorRate: -0.1}},
		{"hang rate above 1", Config{HangRate: 2}},
		{"status too low", Config{ErrorStatus: 42}},
		{"status too high", Config{ErrorStatus: 900}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := New(tt.cfg); err == nil {
				t.Errorf("New(%+v) = nil error, want error", tt.cfg)
			}
		})
	}
}

func TestActive(t *testing.T) {
	tests := []struct {
		name string
		cfg  Config
		want bool
	}{
		{"empty", Config{}, false},
		{"only a status", Config{ErrorStatus: 500}, false},
		{"latency", Config{Latency: time.Millisecond}, true},
		{"error rate", Config{ErrorRate: 0.5}, true},
		{"hang rate", Config{HangRate: 0.5}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			i, err := New(tt.cfg)
			if err != nil {
				t.Fatal(err)
			}
			if got := i.Active(); got != tt.want {
				t.Errorf("Active() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestErrorRateOneAlwaysFires(t *testing.T) {
	var reached atomic.Int64
	i, err := New(Config{ErrorRate: 1, ErrorStatus: http.StatusServiceUnavailable})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(i.Middleware(okHandler(&reached)))
	defer srv.Close()

	for n := 0; n < 10; n++ {
		resp, err := srv.Client().Get(srv.URL)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusServiceUnavailable {
			t.Fatalf("status = %d, want 503", resp.StatusCode)
		}
		if resp.Header.Get(Header) != "error" {
			t.Errorf("%s = %q, want error", Header, resp.Header.Get(Header))
		}
	}
	if reached.Load() != 0 {
		t.Errorf("handler reached %d times, want 0", reached.Load())
	}
}

func TestErrorRateZeroNeverFires(t *testing.T) {
	var reached atomic.Int64
	i, err := New(Config{Latency: time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(i.Middleware(okHandler(&reached)))
	defer srv.Close()

	for n := 0; n < 10; n++ {
		resp, err := srv.Client().Get(srv.URL)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want 200", resp.StatusCode)
		}
	}
	if reached.Load() != 10 {
		t.Errorf("handler reached %d times, want 10", reached.Load())
	}
}

func TestErrorStatusDefaultsTo503(t *testing.T) {
	var reached atomic.Int64
	i, err := New(Config{ErrorRate: 1})
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	i.Middleware(okHandler(&reached)).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", rec.Code)
	}
}

// A test that fails on the third retry has to fail on the third retry again, so
// the roll sequence must be fixed for a given seed.
func TestSameSeedGivesSameSequence(t *testing.T) {
	sequence := func(seed int64) []int {
		var reached atomic.Int64
		i, err := New(Config{ErrorRate: 0.5, Seed: seed})
		if err != nil {
			t.Fatal(err)
		}
		handler := i.Middleware(okHandler(&reached))
		var out []int
		for n := 0; n < 30; n++ {
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
			out = append(out, rec.Code)
		}
		return out
	}

	first, second := sequence(42), sequence(42)
	for i := range first {
		if first[i] != second[i] {
			t.Fatalf("request %d: %d then %d — the sequence must be reproducible",
				i, first[i], second[i])
		}
	}

	// A different seed must actually change something, or Seed does nothing.
	other := sequence(1000)
	same := true
	for i := range first {
		if first[i] != other[i] {
			same = false
			break
		}
	}
	if same {
		t.Error("a different seed produced an identical sequence")
	}
}

func TestErrorRateRoughlyHolds(t *testing.T) {
	var reached atomic.Int64
	i, err := New(Config{ErrorRate: 0.5, Seed: 7})
	if err != nil {
		t.Fatal(err)
	}
	handler := i.Middleware(okHandler(&reached))

	const n = 2000
	errors := 0
	for k := 0; k < n; k++ {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
		if rec.Code == http.StatusServiceUnavailable {
			errors++
		}
	}
	if errors < n*4/10 || errors > n*6/10 {
		t.Errorf("%d/%d errors, want roughly half", errors, n)
	}
}

func TestLatencyIsApplied(t *testing.T) {
	var reached atomic.Int64
	const latency = 60 * time.Millisecond
	i, err := New(Config{Latency: latency})
	if err != nil {
		t.Fatal(err)
	}

	start := time.Now()
	rec := httptest.NewRecorder()
	i.Middleware(okHandler(&reached)).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	elapsed := time.Since(start)

	if elapsed < latency {
		t.Errorf("took %s, want at least %s", elapsed, latency)
	}
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
}

// A client that gives up during the injected delay must not be written to.
func TestLatencyAbortsOnClientCancel(t *testing.T) {
	var reached atomic.Int64
	i, err := New(Config{Latency: 10 * time.Second})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	req := httptest.NewRequest(http.MethodGet, "/", nil).WithContext(ctx)
	done := make(chan struct{})
	go func() {
		i.Middleware(okHandler(&reached)).ServeHTTP(httptest.NewRecorder(), req)
		close(done)
	}()
	cancel()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("the handler kept waiting after the client cancelled")
	}
	if reached.Load() != 0 {
		t.Errorf("handler reached %d times, want 0", reached.Load())
	}
}

// hang_rate is the only way to exercise a client-side timeout path.
func TestHangBlocksUntilClientGivesUp(t *testing.T) {
	var reached atomic.Int64
	i, err := New(Config{HangRate: 1})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	req := httptest.NewRequest(http.MethodGet, "/", nil).WithContext(ctx)

	done := make(chan struct{})
	go func() {
		i.Middleware(okHandler(&reached)).ServeHTTP(httptest.NewRecorder(), req)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("hang did not end when the request context did")
	}
	if reached.Load() != 0 {
		t.Errorf("handler reached %d times, want 0", reached.Load())
	}
}

// rand.Rand is not concurrency-safe; run with -race.
func TestConcurrentRolls(t *testing.T) {
	var reached atomic.Int64
	i, err := New(Config{ErrorRate: 0.5, HangRate: 0})
	if err != nil {
		t.Fatal(err)
	}
	handler := i.Middleware(okHandler(&reached))

	var wg sync.WaitGroup
	wg.Add(50)
	for n := 0; n < 50; n++ {
		go func() {
			defer wg.Done()
			handler.ServeHTTP(httptest.NewRecorder(),
				httptest.NewRequest(http.MethodGet, "/", nil))
		}()
	}
	wg.Wait()
}
