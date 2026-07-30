package scan

import (
	"encoding/base64"
	"net/http"
	"strings"
	"testing"

	"github.com/nhan4013/hrp/internal/cassette"
	"github.com/nhan4013/hrp/internal/redact"
)

// Fixtures are assembled from parts instead of written as whole literals. A
// complete credential-shaped string in the source trips GitHub's push
// protection even when it is synthetic, and the detectors only need the shape.
func shaped(prefix, body string) string { return prefix + body }

var (
	stripeKey = shaped("sk_"+"live_", strings.Repeat("A", 24))
	ghToken   = shaped("gh"+"p_", strings.Repeat("a", 36))
	ghPAT     = shaped("github"+"_pat_", strings.Repeat("A", 30))
	awsKey    = shaped("AK"+"IA", strings.Repeat("Z", 16))
	googleKey = shaped("AI"+"za", strings.Repeat("b", 35))
	slackTok  = shaped("xo"+"xb-", "1234567890-abcdefghij")
	jwtTok    = shaped("ey"+"Jh", "bGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTYifQ.dBjftJeZ4CVP")
)

func mustScanner(t *testing.T, extra ...redact.Pattern) *Scanner {
	t.Helper()
	s, err := New(extra)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return s
}

func TestLuhnValid(t *testing.T) {
	tests := []struct {
		name  string
		digit string
		want  bool
	}{
		{"visa test number", "4111111111111111", true},
		{"mastercard test number", "5555555555554444", true},
		{"amex test number", "378282246310005", true},
		{"spaced", "4111 1111 1111 1111", true},
		{"dashed", "4111-1111-1111-1111", true},
		{"one digit off", "4111111111111112", false},
		{"a large amount", "1500000000000000", false},
		{"epoch millis", "1753876543210", false},
		{"too short", "41111111111", false},
		{"too long", "41111111111111111111", false},
		{"not digits", "4111abcd11111111", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := luhnValid(tt.digit); got != tt.want {
				t.Errorf("luhnValid(%q) = %v, want %v", tt.digit, got, tt.want)
			}
		})
	}
}

func TestBuiltinDetectors(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  string // detector name, "" for no finding
	}{
		{"stripe live key", `{"key":"` + stripeKey + `"}`, "stripe_key"},
		{"github token", ghToken, "github_token"},
		{"github fine-grained", ghPAT, "github_token"},
		{"aws access key", awsKey, "aws_access_key"},
		{"google api key", googleKey, "google_api_key"},
		{"slack token", slackTok, "slack_token"},
		{"jwt", jwtTok, "jwt"},
		{"private key", "-----BEGIN RSA PRIVATE KEY-----", "private_key"},
		{"bearer token", "Bearer abcdefghijklmnopqrst", "bearer_token"},
		{"card number", `{"card":"4111111111111111"}`, "card_number"},

		// Things that must NOT be reported: a scanner that cries wolf gets
		// switched off, and a switched-off scanner protects nothing.
		{"redaction placeholder", redact.Placeholder, ""},
		{"large amount", `{"amount":1500000000000000}`, ""},
		{"epoch millis", `{"ts":1753876543210}`, ""},
		{"ordinary json", `{"id":"ch_123","status":"succeeded"}`, ""},
		{"order number", `{"order":"ORD-2026-000123"}`, ""},
		{"content type", "application/json; charset=utf-8", ""},
		{"invalid card digits", `{"card":"4111111111111112"}`, ""},
	}
	s := mustScanner(t)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := s.text("id", "request.body", tt.value)
			if tt.want == "" {
				if len(got) != 0 {
					t.Errorf("got %v, want no findings", got)
				}
				return
			}
			if len(got) == 0 {
				t.Fatalf("got no findings, want detector %q", tt.want)
			}
			if got[0].Detector != tt.want {
				t.Errorf("detector = %q, want %q", got[0].Detector, tt.want)
			}
		})
	}
}

// The report gets pasted into issues and CI logs, so it must not become a second
// copy of the secret.
func TestFindingExcerptIsMasked(t *testing.T) {
	got := mustScanner(t).text("id", "request.body", stripeKey)
	if len(got) != 1 {
		t.Fatalf("got %d findings, want 1", len(got))
	}
	if strings.Contains(got[0].Excerpt, stripeKey[8:]) {
		t.Errorf("excerpt %q reproduces the secret", got[0].Excerpt)
	}
	if !strings.HasPrefix(got[0].Excerpt, stripeKey[:6]) {
		t.Errorf("excerpt %q should stay recognisable", got[0].Excerpt)
	}
}

func TestScansEveryLocation(t *testing.T) {
	key := stripeKey
	in := cassette.Interaction{
		ID: "abc",
		Request: cassette.Request{
			Method:  http.MethodPost,
			Path:    "/v1/charges",
			Query:   map[string][]string{"api_key": {key}},
			Headers: map[string][]string{"x-vendor-token": {key}},
			Body:    `{"key":"` + key + `"}`,
		},
		Response: cassette.Response{
			Status:  200,
			Headers: map[string][]string{"x-echo": {key}},
			Body:    `{"echo":"` + key + `"}`,
		},
	}

	findings := mustScanner(t).Interactions([]cassette.Interaction{in})

	want := map[string]bool{
		"request.query.api_key":          false,
		"request.headers.x-vendor-token": false,
		"request.body":                   false,
		"response.headers.x-echo":        false,
		"response.body":                  false,
	}
	for _, f := range findings {
		if _, ok := want[f.Location]; ok {
			want[f.Location] = true
		}
	}
	for location, found := range want {
		if !found {
			t.Errorf("nothing reported at %s", location)
		}
	}
}

// A base64-stored body that is really text must not hide from the detectors.
func TestScansBase64StoredTextBody(t *testing.T) {
	key := stripeKey
	in := cassette.Interaction{
		ID:      "b64",
		Request: cassette.Request{Method: http.MethodGet, Path: "/x"},
		Response: cassette.Response{
			Status:       200,
			Body:         base64.StdEncoding.EncodeToString([]byte(`{"key":"` + key + `"}`)),
			BodyEncoding: cassette.EncodingBase64,
		},
	}
	findings := mustScanner(t).Interactions([]cassette.Interaction{in})
	if len(findings) == 0 {
		t.Error("a base64-stored text body was not scanned")
	}
}

func TestConfigPatternsBecomeDetectors(t *testing.T) {
	// A national ID cannot be told from a timestamp by shape alone, which is why
	// it is not built in — but a project that knows its own data can add it.
	s := mustScanner(t, redact.Pattern{Name: "vn_id_number", Regex: `\b\d{12}\b`})

	got := s.text("id", "request.body", `{"id_number":"012345678901"}`)
	if len(got) != 1 {
		t.Fatalf("got %d findings, want 1", len(got))
	}
	if got[0].Detector != "vn_id_number" {
		t.Errorf("detector = %q, want vn_id_number", got[0].Detector)
	}

	// The same value must be clean without the config pattern.
	if got := mustScanner(t).text("id", "request.body", `{"id_number":"012345678901"}`); len(got) != 0 {
		t.Errorf("built-in detectors reported %v, want nothing", got)
	}
}

func TestNewRejectsBadPattern(t *testing.T) {
	if _, err := New([]redact.Pattern{{Name: "bad", Regex: `([`}}); err == nil {
		t.Error("New with an uncompilable regex = nil error, want error")
	}
}

// A clean cassette is the whole point: the common case must report nothing.
func TestRedactedCassetteIsClean(t *testing.T) {
	in := cassette.Interaction{
		ID: "clean",
		Request: cassette.Request{
			Method:  http.MethodPost,
			Path:    "/v1/charges",
			Headers: map[string][]string{"authorization": {redact.Placeholder}},
			Body:    `{"amount":1500000,"card":"` + redact.Placeholder + `"}`,
		},
		Response: cassette.Response{Status: 201, Body: `{"id":"ch_123","status":"succeeded"}`},
	}
	if got := mustScanner(t).Interactions([]cassette.Interaction{in}); len(got) != 0 {
		t.Errorf("a properly redacted cassette reported %v, want nothing", got)
	}
}
