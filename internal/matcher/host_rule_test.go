package matcher

import (
	"testing"

	"github.com/nhan4013/hrp/internal/cassette"
)

func TestHostRule(t *testing.T) {
	tests := []struct {
		name     string
		recorded cassette.Request
		incoming cassette.Request
		wantOK   bool
	}{
		{
			"same host and scheme",
			cassette.Request{Scheme: "https", Host: "api.vendor.com"},
			cassette.Request{Scheme: "https", Host: "api.vendor.com"},
			true,
		},
		{
			"host case differs",
			cassette.Request{Scheme: "https", Host: "API.vendor.com"},
			cassette.Request{Scheme: "https", Host: "api.vendor.com"},
			true,
		},
		{
			"different host, same path",
			cassette.Request{Scheme: "https", Host: "a.com"},
			cassette.Request{Scheme: "https", Host: "b.com"},
			false,
		},
		{
			"different scheme, same host",
			cassette.Request{Scheme: "https", Host: "a.com"},
			cassette.Request{Scheme: "http", Host: "a.com"},
			false,
		},
		{
			"reverse-proxy cassette has no host: wildcard",
			cassette.Request{},
			cassette.Request{Scheme: "https", Host: "a.com"},
			true,
		},
		{
			"empty scheme is a wildcard",
			cassette.Request{Host: "a.com"},
			cassette.Request{Scheme: "https", Host: "a.com"},
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := hostRule{}.Compare(&tt.recorded, &tt.incoming)
			if ok := got == nil; ok != tt.wantOK {
				t.Errorf("match = %v, want %v (mismatch: %+v)", ok, tt.wantOK, got)
			}
		})
	}
}

// New must accept the host rule by name, since MITM matching configures it
// from a string list like every other rule.
func TestNewAcceptsHostRule(t *testing.T) {
	m, err := New([]string{"method", "host", "path", "query", "body"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	agree := m.Compare(
		&cassette.Request{Method: "GET", Scheme: "https", Host: "a.com", Path: "/x"},
		&cassette.Request{Method: "GET", Scheme: "https", Host: "a.com", Path: "/x"},
	)
	if !agree.OK() {
		t.Errorf("identical requests should match: %+v", agree.Mismatches)
	}
	disagree := m.Compare(
		&cassette.Request{Method: "GET", Scheme: "https", Host: "a.com", Path: "/x"},
		&cassette.Request{Method: "GET", Scheme: "https", Host: "b.com", Path: "/x"},
	)
	if disagree.OK() {
		t.Error("different hosts should not match")
	}
}
