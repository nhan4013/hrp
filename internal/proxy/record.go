package proxy

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/nhan4013/hrp/internal/cassette"
	"github.com/nhan4013/hrp/internal/redact"
)

type recorder struct {
	store    *cassette.Store
	redactor *redact.Redactor
}

// pending carries the captured request from the inbound handler to
// ModifyResponse, which is where the pair becomes an interaction.
type pending struct {
	req     cassette.Request
	start   time.Time
	skipped bool
}

// ctxKey keys pending inside the request context. A distinct unexported type
// cannot collide with keys set by other packages.
type ctxKey struct{}

// captureRequest buffers the request body so it can be recorded, then re-injects
// it for the forwarded request. http.Request.Body is a stream: reading it once
// consumes it, and whatever is not put back never reaches the upstream.
func (rec *recorder) captureRequest(r *http.Request) *pending {
	p := &pending{start: time.Now()}

	raw, replacement, captured := cassette.CaptureBody(r.Body, cassette.MaxBodySize)
	if replacement != nil {
		r.Body = replacement
	}
	if !captured {
		p.skipped = true
		slog.Warn("request body too large to record, forwarding without recording",
			"method", r.Method, "path", r.URL.Path, "limit_bytes", cassette.MaxBodySize)
		return p
	}

	// Redact before building the cassette form, not after. NewRequest hashes the
	// body, and a sha256 of a 16-digit card number is brute-forceable: the hash
	// has to be of the redacted bytes. r.Body still holds the originals.
	p.req = cassette.NewRequest(r, rec.redactor.Body(raw))
	rec.redactor.Headers(p.req.Headers)
	return p
}

// modifyResponse buffers the response body, pairs it with the captured request
// and appends the interaction. It runs inside httputil.ReverseProxy, before the
// response is written back to the client.
func (rec *recorder) modifyResponse(resp *http.Response) error {
	p, ok := resp.Request.Context().Value(ctxKey{}).(*pending)
	if !ok || p.skipped {
		return nil
	}

	raw, replacement, captured := cassette.CaptureBody(resp.Body, cassette.MaxBodySize)
	if replacement != nil {
		resp.Body = replacement
	}
	if !captured {
		slog.Warn("response body too large to record",
			"path", p.req.Path, "limit_bytes", cassette.MaxBodySize)
		return nil
	}

	// NewResponse copies the header map, so redacting it does not change what
	// the client receives — only what lands on disk.
	res := cassette.NewResponse(resp, rec.redactor.Body(raw), time.Since(p.start))
	rec.redactor.Headers(res.Headers)

	rec.store.Append(cassette.Interaction{
		ID:       cassette.ID(p.req),
		Request:  p.req,
		Response: res,
		Meta:     cassette.Meta{RecordedAt: time.Now()},
	})
	return nil
}
