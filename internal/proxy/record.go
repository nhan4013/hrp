package proxy

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/nhan4013/hrp/internal/cassette"
	"github.com/nhan4013/hrp/internal/redact"
)

// maxBodySize caps how much of a body is buffered for recording. A body over the
// cap is still proxied byte for byte, it just does not end up in the cassette:
// a 2 GiB upload must not take the proxy down with it.
const maxBodySize = 10 << 20 // 10 MiB

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

	raw, replacement, captured := captureBody(r.Body, maxBodySize)
	if replacement != nil {
		r.Body = replacement
	}
	if !captured {
		p.skipped = true
		slog.Warn("request body too large to record, forwarding without recording",
			"method", r.Method, "path", r.URL.Path, "limit_bytes", maxBodySize)
		return p
	}

	p.req = cassette.NewRequest(r, raw)
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

	raw, replacement, captured := captureBody(resp.Body, maxBodySize)
	if replacement != nil {
		resp.Body = replacement
	}
	if !captured {
		slog.Warn("response body too large to record",
			"path", p.req.Path, "limit_bytes", maxBodySize)
		return nil
	}

	// NewResponse copies the header map, so redacting it does not change what
	// the client receives — only what lands on disk.
	res := cassette.NewResponse(resp, raw, time.Since(p.start))
	rec.redactor.Headers(res.Headers)

	rec.store.Append(cassette.Interaction{
		ID:       cassette.ID(p.req),
		Request:  p.req,
		Response: res,
		Meta:     cassette.Meta{RecordedAt: time.Now()},
	})
	return nil
}

// captureBody buffers up to limit bytes and returns a replacement body.
//
// captured is false when the body is over the limit or could not be read. In
// that case the replacement still carries every byte read so far followed by the
// rest of the stream, so the request or response is relayed intact — there is
// simply nothing safe to record.
func captureBody(rc io.ReadCloser, limit int64) (raw []byte, replacement io.ReadCloser, captured bool) {
	if rc == nil || rc == http.NoBody {
		return nil, nil, true
	}

	buf, err := io.ReadAll(io.LimitReader(rc, limit+1))
	if err != nil || int64(len(buf)) > limit {
		return nil, bodyReader{
			Reader: io.MultiReader(bytes.NewReader(buf), rc),
			Closer: rc,
		}, false
	}

	_ = rc.Close()
	return buf, io.NopCloser(bytes.NewReader(buf)), true
}

// bodyReader re-attaches the original Closer to a re-assembled stream, so the
// underlying connection still gets released.
type bodyReader struct {
	io.Reader
	io.Closer
}
