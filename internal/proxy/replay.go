package proxy

import (
	"fmt"
	"io"
	"log/slog"
	"net/http"

	"github.com/nhan4013/hrp/internal/cassette"
	"github.com/nhan4013/hrp/internal/matcher"
	"github.com/nhan4013/hrp/internal/redact"
)

// statusNoMatch is returned when replay finds nothing to serve. 599 is outside
// the range any real API returns, so a miss can never be mistaken for a genuine
// vendor error.
const statusNoMatch = 599

// replayHeader tells the caller whether a response came from the cassette.
const replayHeader = "X-Hrp-Replay"

// replayer serves responses from a cassette.
//
// With no fallback it never reaches the network: that is strict replay, and a
// miss is an error. With a fallback (auto mode) a miss is forwarded upstream and
// recorded, so the cassette fills in as you work.
type replayer struct {
	store    *cassette.Store
	matcher  *matcher.Matcher
	redactor *redact.Redactor
	fallback http.Handler
}

func (rp *replayer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	raw, replacement, captured := captureBody(r.Body, maxBodySize)
	if replacement != nil {
		r.Body = replacement
	}
	if !captured {
		// Matching without the body would mean matching on less than was
		// recorded, which could serve the wrong response. Refuse instead —
		// unless there is an upstream to ask, in which case just forward.
		if rp.fallback != nil {
			slog.Warn("auto: body over limit, forwarding without matching",
				"method", r.Method, "path", r.URL.Path)
			rp.fallback.ServeHTTP(w, r)
			return
		}
		writeMiss(w, fmt.Sprintf("Request body exceeds the %d byte record limit, "+
			"so it cannot be matched against the cassette.\n", maxBodySize))
		slog.Warn("replay refused: body over limit",
			"method", r.Method, "path", r.URL.Path)
		return
	}

	// Normalize and redact exactly as recording does, so both sides of the
	// comparison have been through the same transformation. Without this, body
	// redaction would break matching: the recorded body holds the placeholder
	// where the incoming one holds the real value.
	req := cassette.NewRequest(r, rp.redactor.Body(raw))
	rp.redactor.Headers(req.Headers)

	candidates := rp.store.Interactions()
	index, res, found := rp.matcher.Best(candidates, &req)

	if found && res.OK() {
		hit := candidates[index]
		rp.store.MarkHit(hit.ID)
		slog.Info("replay hit", "method", req.Method, "path", req.Path, "id", hit.ID)
		writeRecorded(w, hit.Response)
		return
	}

	if rp.fallback != nil {
		// The body was buffered and put back above, so the recorder downstream
		// reads it again from memory rather than from the wire.
		slog.Info("auto: miss, forwarding upstream to record",
			"method", req.Method, "path", req.Path, "best_score", res.Score)
		rp.fallback.ServeHTTP(w, r)
		return
	}

	var best *cassette.Interaction
	if found {
		best = &candidates[index]
	}
	report := matcher.Explain(&req, best, res)
	slog.Warn("replay miss", "method", req.Method, "path", req.Path,
		"candidates", len(candidates), "best_score", res.Score)
	writeMiss(w, report)
}

// writeRecorded replays a stored response.
func writeRecorded(w http.ResponseWriter, res cassette.Response) {
	body, err := cassette.DecodeBody(res.Body, res.BodyEncoding)
	if err != nil {
		slog.Error("corrupt recorded body", "err", err)
		writeMiss(w, "The recorded response body could not be decoded: "+err.Error()+"\n")
		return
	}
	for name, values := range res.Headers {
		for _, value := range values {
			w.Header().Add(name, value)
		}
	}
	w.Header().Set(replayHeader, "hit")
	w.WriteHeader(res.Status)
	if _, err := w.Write(body); err != nil {
		slog.Error("write replayed body", "err", err)
	}
}

func writeMiss(w http.ResponseWriter, report string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set(replayHeader, "miss")
	w.WriteHeader(statusNoMatch)
	if _, err := io.WriteString(w, report); err != nil {
		slog.Error("write miss report", "err", err)
	}
}
