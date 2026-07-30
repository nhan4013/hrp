// Package cassette defines the on-disk format for recorded HTTP interactions.
package cassette

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"
)

// Version is the cassette format version written by this build.
const Version = 1

// EncodingBase64 marks a body that is not printable UTF-8 text. An absent
// encoding means the body is stored verbatim, which keeps JSON payloads
// readable in the file and in PR diffs.
const EncodingBase64 = "base64"

// volatileHeaders are dropped on the write path. Three reasons, all of which
// come down to a cassette having to be stable and portable:
//
//   - Per-request noise (date, trace ids) would make every re-record a diff.
//   - Hop-by-hop headers (RFC 7230 s6.1) describe one connection, not the
//     request, so they must never take part in matching.
//   - Client-specific headers differ per HTTP library: Python sends
//     "accept-encoding: identity" and "connection: close" where Go sends
//     "gzip" and nothing. Recording them would make a cassette taken from a
//     Python service fail to match the same call from a Go service, which
//     defeats the point of a language-agnostic proxy.
//
// content-length is dropped as well: it is implied by the body and goes stale
// the moment redaction rewrites that body.
var volatileHeaders = map[string]struct{}{
	// per-request noise
	"date":            {},
	"user-agent":      {},
	"x-request-id":    {},
	"x-amzn-trace-id": {},
	"traceparent":     {},
	"tracestate":      {},
	// hop-by-hop
	"connection":          {},
	"keep-alive":          {},
	"proxy-authenticate":  {},
	"proxy-authorization": {},
	// Not in RFC 7230 but just as hop-by-hop: curl sends it through every
	// forward proxy, and it says nothing about the request itself.
	"proxy-connection":  {},
	"te":                {},
	"trailer":           {},
	"transfer-encoding": {},
	"upgrade":           {},
	// client-specific
	"accept-encoding": {},
	"content-length":  {},
}

type Cassette struct {
	Version      int           `yaml:"version"`
	Name         string        `yaml:"name"`
	RecordedAt   time.Time     `yaml:"recorded_at"`
	Upstream     string        `yaml:"upstream"`
	Interactions []Interaction `yaml:"interactions"`
}

type Interaction struct {
	ID       string   `yaml:"id"`
	Request  Request  `yaml:"request"`
	Response Response `yaml:"response"`
	Meta     Meta     `yaml:"meta"`
}

type Request struct {
	Method string `yaml:"method"`
	// Scheme and Host are set only for requests recorded through the MITM
	// forward proxy, which serves many upstreams in one cassette. The reverse
	// proxy has a single configured upstream, so both stay empty there and
	// reverse-proxy cassettes keep their exact old shape.
	Scheme       string              `yaml:"scheme,omitempty"`
	Host         string              `yaml:"host,omitempty"`
	Path         string              `yaml:"path"`
	Query        map[string][]string `yaml:"query,omitempty"`
	Headers      map[string][]string `yaml:"headers,omitempty"`
	Body         string              `yaml:"body,omitempty"`
	BodyEncoding string              `yaml:"body_encoding,omitempty"`
	BodyHash     string              `yaml:"body_hash,omitempty"`
}

type Response struct {
	Status       int                 `yaml:"status"`
	Headers      map[string][]string `yaml:"headers,omitempty"`
	Body         string              `yaml:"body,omitempty"`
	BodyEncoding string              `yaml:"body_encoding,omitempty"`
	DurationMS   int64               `yaml:"duration_ms"`
}

type Meta struct {
	HitCount   int       `yaml:"hit_count"`
	RecordedAt time.Time `yaml:"recorded_at"`
}

// NewRequest converts an inbound request plus its already-buffered body into
// the cassette representation. The returned maps are fresh copies, so redacting
// them does not touch what gets forwarded upstream.
func NewRequest(r *http.Request, body []byte) Request {
	req := Request{
		Method:   r.Method,
		Path:     r.URL.Path,
		Query:    normalizeQuery(r.URL.Query()),
		Headers:  normalizeHeaders(r.Header),
		BodyHash: HashBody(body),
	}
	// A forward-proxy request carries an absolute URL; a reverse-proxy request
	// does not (its host lives in the configured upstream, not in each request).
	if r.URL.Host != "" {
		req.Scheme = r.URL.Scheme
		req.Host = strings.ToLower(r.URL.Host)
	}
	req.Body, req.BodyEncoding = encodeBody(body)
	return req
}

// NewResponse converts an upstream response plus its already-buffered body.
func NewResponse(resp *http.Response, body []byte, took time.Duration) Response {
	res := Response{
		Status:     resp.StatusCode,
		Headers:    normalizeHeaders(resp.Header),
		DurationMS: took.Milliseconds(),
	}
	res.Body, res.BodyEncoding = encodeBody(body)
	return res
}

// ID derives a stable identifier from the request. It is content-derived rather
// than random so that re-recording the same traffic does not churn the file.
// Headers are excluded on purpose: they carry redacted and volatile values.
func ID(req Request) string {
	h := sha256.New()
	// Host identity is mixed in only when present, so an interaction recorded
	// through the reverse proxy keeps the ID it has always had.
	if req.Host != "" {
		_, _ = fmt.Fprintf(h, "%s\n%s\n", req.Scheme, req.Host)
	}
	_, _ = fmt.Fprintf(h, "%s\n%s\n%s\n%s",
		req.Method, req.Path, url.Values(req.Query).Encode(), req.BodyHash)
	return hex.EncodeToString(h.Sum(nil))[:12]
}

// HashBody returns a content hash for a body, or "" when there is no body.
func HashBody(body []byte) string {
	if len(body) == 0 {
		return ""
	}
	sum := sha256.Sum256(body)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// DecodeBody returns the raw bytes behind a stored body.
func DecodeBody(body, encoding string) ([]byte, error) {
	switch encoding {
	case "":
		return []byte(body), nil
	case EncodingBase64:
		raw, err := base64.StdEncoding.DecodeString(body)
		if err != nil {
			return nil, fmt.Errorf("decode base64 body: %w", err)
		}
		return raw, nil
	default:
		return nil, fmt.Errorf("unknown body encoding %q", encoding)
	}
}

func encodeBody(raw []byte) (body, encoding string) {
	if len(raw) == 0 {
		return "", ""
	}
	if printableUTF8(raw) {
		return string(raw), ""
	}
	return base64.StdEncoding.EncodeToString(raw), EncodingBase64
}

// printableUTF8 reports whether raw can be stored verbatim in YAML. Control
// characters other than tab, newline and carriage return force base64: YAML
// cannot round-trip them safely.
func printableUTF8(raw []byte) bool {
	if !utf8.Valid(raw) {
		return false
	}
	for _, r := range string(raw) {
		switch {
		case r == '\t' || r == '\n' || r == '\r':
		case r < 0x20 || r == 0x7f:
			return false
		}
	}
	return true
}

// normalizeHeaders lowercases header names and drops the volatile ones. It
// returns nil for an empty result so the field is omitted from the YAML.
func normalizeHeaders(h http.Header) map[string][]string {
	if len(h) == 0 {
		return nil
	}
	out := make(map[string][]string, len(h))
	for name, values := range h {
		key := strings.ToLower(name)
		if _, skip := volatileHeaders[key]; skip {
			continue
		}
		out[key] = append([]string(nil), values...)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func normalizeQuery(q url.Values) map[string][]string {
	if len(q) == 0 {
		return nil
	}
	return q
}
