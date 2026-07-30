package cassette

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestBodyRoundTrip(t *testing.T) {
	tests := []struct {
		name     string
		raw      []byte
		wantEnc  string
		wantBody string
	}{
		{"empty", nil, "", ""},
		{"json", []byte(`{"amount":1500000}`), "", `{"amount":1500000}`},
		{"multiline", []byte("line1\nline2\t\r\n"), "", "line1\nline2\t\r\n"},
		{"utf8 vietnamese", []byte("Nguyễn Văn A"), "", "Nguyễn Văn A"},
		{"gzip magic bytes", []byte{0x1f, 0x8b, 0x08, 0x00}, EncodingBase64, "H4sIAA=="},
		{"invalid utf8", []byte{0xff, 0xfe, 0xfd}, EncodingBase64, "//79"},
		{"nul byte", []byte("a\x00b"), EncodingBase64, "YQBi"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, enc := encodeBody(tt.raw)
			if enc != tt.wantEnc {
				t.Errorf("encoding = %q, want %q", enc, tt.wantEnc)
			}
			if body != tt.wantBody {
				t.Errorf("body = %q, want %q", body, tt.wantBody)
			}
			back, err := DecodeBody(body, enc)
			if err != nil {
				t.Fatalf("DecodeBody: %v", err)
			}
			if !bytes.Equal(back, tt.raw) {
				t.Errorf("round trip = %q, want %q", back, tt.raw)
			}
		})
	}
}

func TestDecodeBodyRejectsUnknownEncoding(t *testing.T) {
	if _, err := DecodeBody("x", "rot13"); err == nil {
		t.Error("DecodeBody with unknown encoding = nil error, want error")
	}
	if _, err := DecodeBody("!!not base64!!", EncodingBase64); err == nil {
		t.Error("DecodeBody with invalid base64 = nil error, want error")
	}
}

// The ID must be stable across runs and across header noise, but must change
// when anything the matcher cares about changes.
func TestIDIsStableAndContentSensitive(t *testing.T) {
	base := Request{
		Method:   http.MethodPost,
		Path:     "/v1/charges",
		Query:    map[string][]string{"currency": {"VND"}},
		Headers:  map[string][]string{"x-request-id": {"abc"}},
		BodyHash: HashBody([]byte(`{"amount":1}`)),
	}
	want := ID(base)
	if want == "" {
		t.Fatal("ID = empty")
	}
	if got := ID(base); got != want {
		t.Errorf("ID not stable: %q then %q", want, got)
	}

	sameButOtherHeaders := base
	sameButOtherHeaders.Headers = map[string][]string{"x-request-id": {"zzz"}}
	if got := ID(sameButOtherHeaders); got != want {
		t.Errorf("ID changed with headers: %q, want %q", got, want)
	}

	differs := []struct {
		name   string
		mutate func(*Request)
	}{
		{"method", func(r *Request) { r.Method = http.MethodGet }},
		{"path", func(r *Request) { r.Path = "/v1/refunds" }},
		{"query", func(r *Request) { r.Query = map[string][]string{"currency": {"USD"}} }},
		{"body", func(r *Request) { r.BodyHash = HashBody([]byte(`{"amount":2}`)) }},
	}
	for _, d := range differs {
		t.Run(d.name, func(t *testing.T) {
			req := base
			d.mutate(&req)
			if got := ID(req); got == want {
				t.Errorf("ID unchanged after %s change", d.name)
			}
		})
	}
}

func TestNewRequestNormalizesHeaders(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/v1/charges?currency=VND",
		strings.NewReader(`{"amount":1}`))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer secret")
	r.Header.Set("User-Agent", "curl/8.0")      // per-request noise
	r.Header.Set("X-Request-Id", "req-1")       // per-request noise
	r.Header.Set("Content-Length", "12")        // implied by the body
	r.Header.Set("Connection", "close")         // hop-by-hop
	r.Header.Set("Accept-Encoding", "identity") // client-specific
	r.Header.Add("X-Multi", "a")
	r.Header.Add("X-Multi", "b")

	req := NewRequest(r, []byte(`{"amount":1}`))

	if _, ok := req.Headers["Content-Type"]; ok {
		t.Error("header keys not lowercased")
	}
	if got := req.Headers["content-type"]; len(got) != 1 || got[0] != "application/json" {
		t.Errorf("content-type = %v, want [application/json]", got)
	}
	for _, dropped := range []string{
		"user-agent", "x-request-id", "content-length", "connection", "accept-encoding",
	} {
		if _, ok := req.Headers[dropped]; ok {
			t.Errorf("volatile header %q was recorded", dropped)
		}
	}
	if got := req.Headers["x-multi"]; len(got) != 2 {
		t.Errorf("x-multi = %v, want 2 values", got)
	}
	if got := req.Query["currency"]; len(got) != 1 || got[0] != "VND" {
		t.Errorf("query currency = %v, want [VND]", got)
	}
	if !strings.HasPrefix(req.BodyHash, "sha256:") {
		t.Errorf("body_hash = %q, want sha256: prefix", req.BodyHash)
	}
}

// NewRequest must not alias the inbound header map: redacting the cassette copy
// would otherwise strip the real Authorization header before it is forwarded.
func TestNewRequestCopiesHeaders(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Bearer secret")

	req := NewRequest(r, nil)
	req.Headers["authorization"][0] = "<REDACTED>"

	if got := r.Header.Get("Authorization"); got != "Bearer secret" {
		t.Errorf("inbound header mutated to %q", got)
	}
}

// Serializing the same cassette twice must produce identical bytes, otherwise
// every re-record shows up as a diff.
func TestMarshalIsDeterministic(t *testing.T) {
	c := &Cassette{
		Version: Version,
		Name:    "payments",
		Interactions: []Interaction{{
			ID: "abc123",
			Request: Request{
				Method: http.MethodPost,
				Path:   "/v1/charges",
				Headers: map[string][]string{
					"zeta": {"1"}, "alpha": {"2"}, "content-type": {"application/json"},
				},
				Query: map[string][]string{"b": {"2"}, "a": {"1"}},
			},
			Response: Response{Status: 201},
		}},
	}
	first, err := yaml.Marshal(c)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for i := 0; i < 20; i++ {
		again, err := yaml.Marshal(c)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		if !bytes.Equal(first, again) {
			t.Fatalf("marshal not deterministic on run %d:\n%s\nvs\n%s", i, first, again)
		}
	}
}
