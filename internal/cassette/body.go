package cassette

import (
	"bytes"
	"io"
	"net/http"
)

// MaxBodySize caps how much of a body is buffered for recording. A body over
// the cap is still relayed byte for byte, it just does not end up in the
// cassette: a 2 GiB upload must not take the proxy down with it.
//
// Shared by every engine that records — the reverse proxy and the MITM forward
// proxy both have to enforce the same limit the same way.
const MaxBodySize = 10 << 20 // 10 MiB

// CaptureBody buffers up to limit bytes and returns a replacement body.
//
// captured is false when the body is over the limit or could not be read. In
// that case replacement still carries every byte read so far followed by the
// rest of the stream, so the request or response is relayed intact — there is
// simply nothing safe to record.
func CaptureBody(rc io.ReadCloser, limit int64) (raw []byte, replacement io.ReadCloser, captured bool) {
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
