// Package fault injects failures into proxied traffic, so an application's retry
// and circuit-breaker code can be exercised without asking a vendor to break.
package fault

import (
	"fmt"
	"log/slog"
	"math/rand"
	"net/http"
	"sync"
	"time"
)

// Header marks a response the injector produced rather than the upstream or the
// cassette, so a confusing 503 can be traced back to configuration.
const Header = "X-Hrp-Fault"

// defaultSeed keeps a run reproducible. A test that fails on the third retry
// should fail on the third retry again, which is only true if the sequence of
// rolls is fixed. Set Seed to vary it deliberately.
const defaultSeed = 1

// Config describes which failures to inject.
type Config struct {
	// Latency is added to every request.
	Latency time.Duration
	// ErrorRate is the probability, 0 to 1, of answering with ErrorStatus.
	ErrorRate float64
	// ErrorStatus is the status to answer with. Defaults to 503.
	ErrorStatus int
	// HangRate is the probability of never answering, so the client hits its own
	// timeout. This is the only way to exercise a client-side timeout path.
	HangRate float64
	// Seed fixes the random sequence. Zero means defaultSeed.
	Seed int64
}

// Injector applies a Config to requests.
type Injector struct {
	cfg Config

	// rand.Rand is not safe for concurrent use and the proxy is concurrent by
	// nature, so every roll goes through the mutex.
	mu   sync.Mutex
	rand *rand.Rand
}

// New validates cfg and returns an Injector.
func New(cfg Config) (*Injector, error) {
	if cfg.Latency < 0 {
		return nil, fmt.Errorf("fault: latency %s is negative", cfg.Latency)
	}
	if err := checkRate("error_rate", cfg.ErrorRate); err != nil {
		return nil, err
	}
	if err := checkRate("hang_rate", cfg.HangRate); err != nil {
		return nil, err
	}
	if cfg.ErrorStatus == 0 {
		cfg.ErrorStatus = http.StatusServiceUnavailable
	}
	if cfg.ErrorStatus < 100 || cfg.ErrorStatus > 599 {
		return nil, fmt.Errorf("fault: error_status %d is not a valid HTTP status",
			cfg.ErrorStatus)
	}
	seed := cfg.Seed
	if seed == 0 {
		seed = defaultSeed
	}
	return &Injector{cfg: cfg, rand: rand.New(rand.NewSource(seed))}, nil
}

func checkRate(name string, rate float64) error {
	if rate < 0 || rate > 1 {
		return fmt.Errorf("fault: %s %v is outside 0..1", name, rate)
	}
	return nil
}

// Active reports whether this Injector would ever do anything, so a config with
// everything switched off can skip the middleware entirely.
func (i *Injector) Active() bool {
	return i.cfg.Latency > 0 || i.cfg.ErrorRate > 0 || i.cfg.HangRate > 0
}

// Middleware wraps next, injecting failures before it is reached.
func (i *Injector) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if i.cfg.Latency > 0 {
			select {
			case <-time.After(i.cfg.Latency):
			case <-r.Context().Done():
				// The client gave up during the injected delay. Writing a
				// response now would only log a broken pipe.
				return
			}
		}

		if i.roll(i.cfg.HangRate) {
			slog.Warn("fault: hanging until the client gives up",
				"method", r.Method, "path", r.URL.Path)
			<-r.Context().Done()
			return
		}

		if i.roll(i.cfg.ErrorRate) {
			slog.Warn("fault: injecting error",
				"method", r.Method, "path", r.URL.Path, "status", i.cfg.ErrorStatus)
			w.Header().Set(Header, "error")
			w.WriteHeader(i.cfg.ErrorStatus)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// roll reports whether an event with the given probability fires.
func (i *Injector) roll(rate float64) bool {
	if rate <= 0 {
		return false
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.rand.Float64() < rate
}
