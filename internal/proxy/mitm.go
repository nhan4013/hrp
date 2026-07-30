package proxy

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sync"

	"github.com/nhan4013/hrp/internal/mitm"
)

// mitmHandler is a forward proxy. Plain HTTP arrives in absolute-form
// ("GET http://host/path") and goes straight to the engine. HTTPS arrives as
// CONNECT, which only names a host: the request itself is inside TLS, so the
// connection is hijacked, terminated with a minted leaf certificate, and the
// decrypted requests go to the same engine.
type mitmHandler struct {
	ca     *mitm.CA
	engine http.Handler
}

func (m *mitmHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		m.connect(w, r)
		return
	}
	if !r.URL.IsAbs() {
		// An origin-form request means the app is pointed at hrp as if hrp were
		// the API itself. That is the reverse proxy's job; a forward proxy only
		// understands absolute-form.
		http.Error(w, "hrp mitm is a forward proxy: keep the app's base URL unchanged "+
			"and set HTTP_PROXY/HTTPS_PROXY to this address instead\n", http.StatusBadRequest)
		return
	}
	m.engine.ServeHTTP(w, r)
}

// connect answers the CONNECT, then turns the hijacked connection into a TLS
// server: from the client's point of view it just did a TLS handshake with the
// real host, from hrp's point of view the requests arrive in plain sight.
func (m *mitmHandler) connect(w http.ResponseWriter, r *http.Request) {
	conn, rw, err := http.NewResponseController(w).Hijack()
	if err != nil {
		// Hijack before writing anything, so a failure here can still be an
		// honest HTTP error rather than a truncated tunnel.
		http.Error(w, fmt.Sprintf("hijack CONNECT: %v", err), http.StatusInternalServerError)
		return
	}

	if _, err := rw.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		slog.Error("answer CONNECT", "authority", r.Host, "err", err)
		_ = conn.Close()
		return
	}
	if err := rw.Flush(); err != nil {
		slog.Error("flush CONNECT answer", "authority", r.Host, "err", err)
		_ = conn.Close()
		return
	}

	// authority is "host:port" — the TCP-level target the client asked for.
	authority := r.Host
	tlsConn := tls.Server(conn, &tls.Config{
		// SNI names the host the client believes it is talking to; mint a leaf
		// for exactly that name. IP literals send no SNI at all (RFC 6066), so
		// fall back to the CONNECT authority.
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			name := hello.ServerName
			if name == "" {
				name = authority
			}
			leaf, err := m.ca.Leaf(name)
			if err != nil {
				slog.Error("mint leaf certificate", "host", name, "err", err)
				return nil, err
			}
			return leaf, nil
		},
	})

	// The stdlib server serving the one tunnel connection gives keep-alive,
	// header timeouts and request parsing for free, where a hand-rolled read
	// loop would get all three subtly wrong. Serve returns as soon as the
	// listener is drained; the connection goroutine outlives it and ends when
	// the client disconnects.
	srv := &http.Server{
		Handler:           logRequests(absolutize(m.engine, "https", authority)),
		ReadHeaderTimeout: readHeaderTimeout,
	}
	err = srv.Serve(&singleConnListener{conn: tlsConn, addr: tlsConn.LocalAddr()})
	// Draining a one-connection listener is how every tunnel ends; only other
	// errors are news.
	if err != nil && !errors.Is(err, net.ErrClosed) {
		slog.Error("serve tunnel", "authority", authority, "err", err)
	}
}

// absolutize fills in what a request inside a CONNECT tunnel does not say:
// the scheme and host the client connected to, which the request line there
// leaves in origin-form.
func absolutize(next http.Handler, scheme, authority string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Scheme == "" {
			r.URL.Scheme = scheme
		}
		if r.URL.Host == "" {
			r.URL.Host = authority
		}
		next.ServeHTTP(w, r)
	})
}

// forwardProxy is the MITM analogue of reverseProxy: instead of rewriting every
// request to one configured upstream, each request's own absolute URL is the
// target. That is the whole difference between a reverse and a forward proxy.
func (s *Server) forwardProxy(rec *recorder) http.Handler {
	rp := &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			// A path-less SetURL keeps the inbound path and query untouched
			// while re-pointing scheme and host, and rewrites the Host header,
			// which vhost routing and TLS SNI need.
			r.SetURL(&url.URL{Scheme: r.In.URL.Scheme, Host: r.In.URL.Host})
		},
		Transport: s.transport,
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			slog.Error("upstream request failed",
				"method", r.Method, "host", r.URL.Host, "path", r.URL.Path, "err", err)
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

// singleConnListener adapts one hijacked connection to net.Listener. After the
// one Accept, further calls report the listener as closed so http.Server.Serve
// winds down instead of spinning on a second connection that can never arrive.
type singleConnListener struct {
	addr net.Addr

	mu   sync.Mutex
	conn net.Conn
}

func (l *singleConnListener) Accept() (net.Conn, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.conn == nil {
		return nil, net.ErrClosed
	}
	conn := l.conn
	l.conn = nil
	return conn, nil
}

func (l *singleConnListener) Close() error { return nil }

func (l *singleConnListener) Addr() net.Addr { return l.addr }
