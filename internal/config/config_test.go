package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const full = `
listen: :9090
upstream: https://sandbox.vendor.com
cassette: ./cassettes/payment.yaml

match:
  on: [method, path, body]
  ignore_query: [timestamp, nonce]

redact:
  headers: [x-vendor-signature]
  json_fields: [card.number, cvv]
  patterns:
    - name: card_number
      regex: '\b\d{13,19}\b'

fault:
  enabled: true
  latency: 200ms
  error_rate: 0.1
  error_status: 503
  hang_rate: 0.05
  seed: 42
`

func TestLoadFull(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hrp.yaml")
	if err := os.WriteFile(path, []byte(full), 0o600); err != nil {
		t.Fatal(err)
	}

	c, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if c.Listen != ":9090" || c.Upstream != "https://sandbox.vendor.com" {
		t.Errorf("listen/upstream = %q/%q", c.Listen, c.Upstream)
	}
	if c.Cassette != "./cassettes/payment.yaml" {
		t.Errorf("cassette = %q", c.Cassette)
	}
	if got := strings.Join(c.Match.On, ","); got != "method,path,body" {
		t.Errorf("match.on = %q", got)
	}
	if got := strings.Join(c.Match.IgnoreQuery, ","); got != "timestamp,nonce" {
		t.Errorf("match.ignore_query = %q", got)
	}
	if got := strings.Join(c.Redact.JSONFields, ","); got != "card.number,cvv" {
		t.Errorf("redact.json_fields = %q", got)
	}
	if len(c.Redact.Patterns) != 1 || c.Redact.Patterns[0].Name != "card_number" {
		t.Errorf("redact.patterns = %+v", c.Redact.Patterns)
	}
	if !c.Fault.Enabled || c.Fault.Latency != 200*time.Millisecond {
		t.Errorf("fault = %+v", c.Fault)
	}
	if c.Fault.ErrorRate != 0.1 || c.Fault.ErrorStatus != 503 ||
		c.Fault.HangRate != 0.05 || c.Fault.Seed != 42 {
		t.Errorf("fault = %+v", c.Fault)
	}
}

func TestLoadEmptyFileIsValid(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hrp.yaml")
	if err := os.WriteFile(path, []byte(""), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err != nil {
		t.Errorf("Load of an empty config = %v, want nil", err)
	}
}

func TestLoadMissingFile(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "nope.yaml")); err == nil {
		t.Error("Load of a missing file = nil error, want error")
	}
}

// A misspelled key that silently does nothing is exactly the failure this file
// exists to prevent.
func TestRejectsUnknownKeys(t *testing.T) {
	tests := []struct {
		name string
		yaml string
	}{
		{"typo at top level", "upstrem: https://vendor.com\n"},
		{"typo in redact", "redact:\n  header: [authorization]\n"},
		{"typo in fault", "fault:\n  error_rat: 0.5\n"},
		{"mode is not a config key", "mode: auto\n"},
		{"ignore_headers is not a config key", "match:\n  ignore_headers: [date]\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := parse([]byte(tt.yaml), "test.yaml"); err == nil {
				t.Errorf("parse(%q) = nil error, want error", tt.yaml)
			}
		})
	}
}

func TestValidationErrors(t *testing.T) {
	tests := []struct {
		name string
		yaml string
		want string
	}{
		{"pattern without regex", "redact:\n  patterns:\n    - name: x\n", "regex"},
		{"empty json field", "redact:\n  json_fields: [\"\"]\n", "json_fields"},
		{"negative latency", "fault:\n  latency: -1s\n", "latency"},
		{"error rate too high", "fault:\n  error_rate: 1.5\n", "error_rate"},
		{"hang rate too high", "fault:\n  hang_rate: 9\n", "hang_rate"},
		{"bad status", "fault:\n  error_status: 42\n", "error_status"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parse([]byte(tt.yaml), "test.yaml")
			if err == nil {
				t.Fatalf("parse(%q) = nil error, want error", tt.yaml)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error %q should name %q", err, tt.want)
			}
		})
	}
}

// A duration without units is rejected rather than guessed at, so "latency: 200"
// cannot silently mean 200 nanoseconds.
func TestDurationNeedsUnits(t *testing.T) {
	if _, err := parse([]byte("fault:\n  latency: 200\n"), "test.yaml"); err == nil {
		t.Error("a unitless latency = nil error, want error")
	}
}

// The shipped example must stay loadable, or it teaches the wrong schema.
func TestExampleConfigIsValid(t *testing.T) {
	c, err := Load("../../hrp.yaml")
	if err != nil {
		t.Fatalf("the example hrp.yaml does not load: %v", err)
	}
	if c.Fault.Enabled {
		t.Error("the example should ship with fault injection off")
	}
}
