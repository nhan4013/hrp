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
	"github.com/nhan4013/hrp/internal/redact"
)

const (
	shutdownTimeout   = 10 * time.Second
	readHeaderTimeout = 10 * time.Second
	flushInterval     = 5 * time.Second
)

// Server is an HTTP reverse proxy in front of a single upstream.
type Server struct {
	upstream *url.URL
	store    *cassette.Store
	http     *http.Server
}

// New builds a Server listening on listen and forwarding to upstream.
// upstream must be an absolute http or https URL. A nil store turns recording
// off and makes the proxy a plain pass-through.
func New(listen, upstream string, store *cassette.Store) (*Server, error) {
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

	var rec *recorder
	if store != nil {
		rec = &recorder{store: store, redactor: redact.New()}
	}

	s := &Server{upstream: target, store: store}
	s.http = &http.Server{
		Addr:              listen,
		Handler:           logRequests(s.reverseProxy(target, rec)),
		ReadHeaderTimeout: readHeaderTimeout,
		// No Read/WriteTimeout: proxied bodies may stream for a long time.
	}
	return s, nil
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
		slog.Info("listening", "addr", s.http.Addr, "upstream", s.upstream.String())
		err := s.http.ListenAndServe()
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	if s.store != nil {
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
	if s.store != nil {
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
