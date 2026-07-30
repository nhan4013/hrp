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
	"github.com/nhan4013/hrp/internal/matcher"
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
)

// Config describes one proxy instance.
type Config struct {
	// Listen is the address to bind, e.g. ":8080".
	Listen string
	// Upstream is the absolute base URL to forward to. Required for every mode
	// except ModeReplay, which never leaves the machine.
	Upstream string
	// Mode defaults to ModePassthrough.
	Mode Mode
	// Store is required for ModeRecord and ModeReplay.
	Store *cassette.Store
	// Matcher is required for ModeReplay.
	Matcher *matcher.Matcher
}

// Server is an HTTP proxy that records or replays interactions with an upstream.
type Server struct {
	mode     Mode
	upstream *url.URL
	store    *cassette.Store
	http     *http.Server
}

// New builds a Server from cfg, rejecting any combination that cannot work.
func New(cfg Config) (*Server, error) {
	if cfg.Mode == "" {
		cfg.Mode = ModePassthrough
	}

	s := &Server{mode: cfg.Mode, store: cfg.Store}

	var handler http.Handler
	switch cfg.Mode {
	case ModeReplay:
		if cfg.Store == nil {
			return nil, errors.New("replay mode needs a cassette")
		}
		if cfg.Matcher == nil {
			return nil, errors.New("replay mode needs a matcher")
		}
		handler = &replayer{
			store:    cfg.Store,
			matcher:  cfg.Matcher,
			redactor: redact.New(),
		}

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
			rec = &recorder{store: cfg.Store, redactor: redact.New()}
		}
		handler = s.reverseProxy(target, rec)

	default:
		return nil, fmt.Errorf("unknown mode %q, want %s, %s or %s",
			cfg.Mode, ModePassthrough, ModeRecord, ModeReplay)
	}

	s.http = &http.Server{
		Addr:              cfg.Listen,
		Handler:           logRequests(handler),
		ReadHeaderTimeout: readHeaderTimeout,
		// No Read/WriteTimeout: proxied bodies may stream for a long time.
	}
	return s, nil
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
		// Replay never forwards, so there is no upstream to report.
		upstream := "none (replay)"
		if s.upstream != nil {
			upstream = s.upstream.String()
		}
		slog.Info("listening", "addr", s.http.Addr, "mode", string(s.mode), "upstream", upstream)
		err := s.http.ListenAndServe()
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	if s.mode == ModeRecord {
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
	if s.mode == ModeRecord {
		if flushErr = s.store.Flush(); flushErr == nil {
			slog.Info("cassette flushed", "interactions", s.store.Len())
		}
	}
	if err := errors.Join(shutdownErr, flushErr); err != nil {
		return fmt.Errorf("shutdown: %w", err)
	}
	return nil
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
