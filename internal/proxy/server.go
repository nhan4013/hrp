// Package proxy implements the HTTP reverse proxy that records and replays
// interactions with an upstream service.
package proxy

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"

	"github.com/nhan4013/hrp/internal/cassette"
	"github.com/nhan4013/hrp/internal/fault"
	"github.com/nhan4013/hrp/internal/matcher"
	"github.com/nhan4013/hrp/internal/mitm"
	"github.com/nhan4013/hrp/internal/redact"
)

const (
	shutdownTimeout   = 10 * time.Second
	readHeaderTimeout = 10 * time.Second
	flushInterval     = 5 * time.Second
)

// Mode selects what the proxy does with each request.
type Mode string

const (
	// ModePassthrough forwards upstream and records nothing.
	ModePassthrough Mode = "passthrough"
	// ModeRecord forwards upstream and records every interaction.
	ModeRecord Mode = "record"
	// ModeReplay serves from the cassette and never touches the network.
	ModeReplay Mode = "replay"
	// ModeAuto serves from the cassette when it can, and otherwise forwards
	// upstream and records the result. This is the day-to-day development mode.
	ModeAuto Mode = "auto"
)

// Config describes one proxy instance.
type Config struct {
	// Listen is the address to bind, e.g. ":8080".
	Listen string
	// Upstream is the absolute base URL to forward to. Required for every mode
	// except ModeReplay, which never leaves the machine. Unused when CA is set.
	Upstream string
	// Mode defaults to ModePassthrough.
	Mode Mode
	// Store is required for every mode except ModePassthrough.
	Store *cassette.Store
	// Matcher is required for ModeReplay and ModeAuto.
	Matcher *matcher.Matcher
	// Redactor defaults to redact.Default(), which covers the sensitive headers
	// and nothing else. Body redaction has to be configured.
	Redactor *redact.Redactor
	// Fault injects failures when non-nil and active.
	Fault *fault.Injector
	// CA turns the server into a MITM forward proxy: CONNECT tunnels are
	// terminated with certificates minted from this CA, and each request's own
	// absolute URL is its upstream. nil keeps the single-upstream reverse proxy.
	CA *mitm.CA
	// Transport carries requests to real upstreams; nil means
	// http.DefaultTransport. Tests use it to trust a test-only CA.
	Transport http.RoundTripper
}

// Server is an HTTP proxy that records or replays interactions with an upstream.
type Server struct {
	mode      Mode
	upstream  *url.URL
	store     *cassette.Store
	ca        *mitm.CA
	transport http.RoundTripper
	http      *http.Server
}

// New builds a Server from cfg, rejecting any combination that cannot work.
func New(cfg Config) (*Server, error) {
	if cfg.Mode == "" {
		cfg.Mode = ModePassthrough
	}
	if cfg.Redactor == nil {
		cfg.Redactor = redact.Default()
	}

	s := &Server{mode: cfg.Mode, store: cfg.Store, ca: cfg.CA, transport: cfg.Transport}

	var handler http.Handler
	var err error
	if cfg.CA != nil {
		handler, err = s.mitmEngine(cfg)
	} else {
		handler, err = s.reverseEngine(cfg)
	}
	if err != nil {
		return nil, err
	}

	// Faults wrap the per-request engine, not the MITM handler: an injected
	// error must look like the vendor failing, not like the tunnel failing.
	if cfg.Fault != nil && cfg.Fault.Active() {
		handler = cfg.Fault.Middleware(handler)
	}

	if cfg.CA != nil {
		handler = &mitmHandler{ca: cfg.CA, engine: handler}
	}

	s.http = &http.Server{
		Addr:              cfg.Listen,
		Handler:           logRequests(handler),
		ReadHeaderTimeout: readHeaderTimeout,
		// No Read/WriteTimeout: proxied bodies may stream for a long time.
	}
	return s, nil
}

// reverseEngine assembles the mode's handler behind a single fixed upstream.
func (s *Server) reverseEngine(cfg Config) (http.Handler, error) {
	switch cfg.Mode {
	case ModeReplay:
		if cfg.Store == nil {
			return nil, errors.New("replay mode needs a cassette")
		}
		if cfg.Matcher == nil {
			return nil, errors.New("replay mode needs a matcher")
		}
		return &replayer{
			store:    cfg.Store,
			matcher:  cfg.Matcher,
			redactor: cfg.Redactor,
		}, nil

	case ModeAuto:
		if cfg.Store == nil {
			return nil, errors.New("auto mode needs a cassette")
		}
		if cfg.Matcher == nil {
			return nil, errors.New("auto mode needs a matcher")
		}
		target, err := parseUpstream(cfg.Upstream)
		if err != nil {
			return nil, err
		}
		s.upstream = target
		rec := &recorder{store: cfg.Store, redactor: cfg.Redactor}
		return &replayer{
			store:    cfg.Store,
			matcher:  cfg.Matcher,
			redactor: cfg.Redactor,
			fallback: s.reverseProxy(target, rec),
		}, nil

	case ModeRecord, ModePassthrough:
		target, err := parseUpstream(cfg.Upstream)
		if err != nil {
			return nil, err
		}
		s.upstream = target

		var rec *recorder
		if cfg.Mode == ModeRecord {
			if cfg.Store == nil {
				return nil, errors.New("record mode needs a cassette")
			}
			rec = &recorder{store: cfg.Store, redactor: cfg.Redactor}
		}
		return s.reverseProxy(target, rec), nil

	default:
		return nil, fmt.Errorf("unknown mode %q, want one of %s, %s, %s, %s",
			cfg.Mode, ModePassthrough, ModeRecord, ModeReplay, ModeAuto)
	}
}

// mitmEngine assembles the same modes, except every request carries its own
// upstream in its absolute URL, so no Upstream is configured or required.
func (s *Server) mitmEngine(cfg Config) (http.Handler, error) {
	switch cfg.Mode {
	case ModeReplay:
		if cfg.Store == nil {
			return nil, errors.New("replay mode needs a cassette")
		}
		if cfg.Matcher == nil {
			return nil, errors.New("replay mode needs a matcher")
		}
		return &replayer{
			store:    cfg.Store,
			matcher:  cfg.Matcher,
			redactor: cfg.Redactor,
		}, nil

	case ModeAuto:
		if cfg.Store == nil {
			return nil, errors.New("auto mode needs a cassette")
		}
		if cfg.Matcher == nil {
			return nil, errors.New("auto mode needs a matcher")
		}
		rec := &recorder{store: cfg.Store, redactor: cfg.Redactor}
		return &replayer{
			store:    cfg.Store,
			matcher:  cfg.Matcher,
			redactor: cfg.Redactor,
			fallback: s.forwardProxy(rec),
		}, nil

	case ModeRecord, ModePassthrough:
		var rec *recorder
		if cfg.Mode == ModeRecord {
			if cfg.Store == nil {
				return nil, errors.New("record mode needs a cassette")
			}
			rec = &recorder{store: cfg.Store, redactor: cfg.Redactor}
		}
		return s.forwardProxy(rec), nil

	default:
		return nil, fmt.Errorf("unknown mode %q, want one of %s, %s, %s, %s",
			cfg.Mode, ModePassthrough, ModeRecord, ModeReplay, ModeAuto)
	}
}

func parseUpstream(upstream string) (*url.URL, error) {
	target, err := url.Parse(upstream)
	if err != nil {
		return nil, fmt.Errorf("parse upstream %q: %w", upstream, err)
	}
	if target.Scheme != "http" && target.Scheme != "https" {
		return nil, fmt.Errorf("upstream %q: scheme must be http or https", upstream)
	}
	if target.Host == "" {
		return nil, fmt.Errorf("upstream %q: missing host", upstream)
	}
	return target, nil
}

func (s *Server) reverseProxy(target *url.URL, rec *recorder) http.Handler {
	rp := &httputil.ReverseProxy{
		// SetURL also rewrites the outbound Host header to the target's host,
		// which third-party APIs need for vhost routing and TLS SNI.
		// X-Forwarded-* headers are deliberately not added: they would change
		// what the vendor sees and add noise to recorded cassettes.
		Rewrite: func(r *httputil.ProxyRequest) {
			r.SetURL(target)
		},
		// nil means http.DefaultTransport; tests inject a CA-trusting one.
		Transport: s.transport,
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			slog.Error("upstream request failed",
				"method", r.Method, "path", r.URL.Path, "err", err)
			w.WriteHeader(http.StatusBadGateway)
		},
	}
	if rec == nil {
		return rp
	}

	rp.ModifyResponse = rec.modifyResponse
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := rec.captureRequest(r)
		rp.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, p)))
	})
}

// Run serves until ctx is cancelled, then shuts down gracefully.
func (s *Server) Run(ctx context.Context) error {
	errCh := make(chan error, 1)
	go func() {
		// Replay never forwards, so there is no upstream to report. MITM has no
		// single upstream either: each request names its own.
		upstream := "none (replay)"
		switch {
		case s.ca != nil:
			upstream = "per request (forward proxy)"
		case s.upstream != nil:
			upstream = s.upstream.String()
		}
		slog.Info("listening", "addr", s.http.Addr, "mode", string(s.mode), "upstream", upstream)
		err := s.http.ListenAndServe()
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	if s.records() {
		go s.flushLoop(ctx)
	}

	select {
	case err := <-errCh:
		return fmt.Errorf("serve: %w", err)
	case <-ctx.Done():
	}

	slog.Info("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()

	// Flush after the server has stopped, so no in-flight request can append an
	// interaction that never reaches disk. Both errors are reported: losing the
	// cassette matters more than a shutdown that timed out, so neither may
	// short-circuit the other.
	shutdownErr := s.http.Shutdown(shutdownCtx)
	var flushErr error
	if s.records() {
		if flushErr = s.store.Flush(); flushErr == nil {
			slog.Info("cassette flushed", "interactions", s.store.Len())
		}
	}
	if err := errors.Join(shutdownErr, flushErr); err != nil {
		return fmt.Errorf("shutdown: %w", err)
	}
	return nil
}

// records reports whether this mode appends to the cassette, and therefore
// whether the cassette needs flushing at all.
func (s *Server) records() bool {
	return s.mode == ModeRecord || s.mode == ModeAuto
}

// flushLoop persists the cassette periodically, so a kill -9 loses at most one
// interval's worth of recording instead of the whole session.
func (s *Server) flushLoop(ctx context.Context) {
	ticker := time.NewTicker(flushInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := s.store.Flush(); err != nil {
				slog.Error("periodic cassette flush", "err", err)
			}
		}
	}
}

// logRequests emits one structured log line per request.
func logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w}
		next.ServeHTTP(rec, r)
		slog.Info("request",
			"method", r.Method,
			"path", r.URL.Path,
			"status", rec.statusCode(),
			"duration_ms", time.Since(start).Milliseconds(),
		)
	})
}

// statusRecorder captures the status code written by the wrapped handler.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

// Unwrap lets http.ResponseController reach the underlying writer, so
// ReverseProxy can still flush streaming responses and hijack connections.
func (w *statusRecorder) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

func (w *statusRecorder) WriteHeader(code int) {
	if w.status == 0 {
		w.status = code
	}
	w.ResponseWriter.WriteHeader(code)
}

// statusCode reports the observed status, defaulting to 200 the way
// net/http does when a handler writes a body without calling WriteHeader.
func (w *statusRecorder) statusCode() int {
	if w.status == 0 {
		return http.StatusOK
	}
	return w.status
}
