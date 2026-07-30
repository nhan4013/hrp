package redact

import (
	"reflect"
	"testing"
)

func TestHeaders(t *testing.T) {
	tests := []struct {
		name  string
		extra []string
		in    map[string][]string
		want  map[string][]string
	}{
		{
			name: "authorization redacted by default",
			in:   map[string][]string{"authorization": {"Bearer secret"}},
			want: map[string][]string{"authorization": {Placeholder}},
		},
		{
			name: "matching is case insensitive",
			in:   map[string][]string{"Authorization": {"Bearer secret"}, "X-API-Key": {"k"}},
			want: map[string][]string{"Authorization": {Placeholder}, "X-API-Key": {Placeholder}},
		},
		{
			name: "value count preserved",
			in:   map[string][]string{"cookie": {"a=1", "b=2"}},
			want: map[string][]string{"cookie": {Placeholder, Placeholder}},
		},
		{
			name: "harmless headers untouched",
			in:   map[string][]string{"content-type": {"application/json"}, "accept": {"*/*"}},
			want: map[string][]string{"content-type": {"application/json"}, "accept": {"*/*"}},
		},
		{
			name:  "extra header from config",
			extra: []string{"X-Vendor-Signature"},
			in:    map[string][]string{"x-vendor-signature": {"sig"}},
			want:  map[string][]string{"x-vendor-signature": {Placeholder}},
		},
		{
			name:  "blank extra entries ignored",
			extra: []string{"", "  "},
			in:    map[string][]string{"": {"weird"}},
			want:  map[string][]string{"": {"weird"}},
		},
		{
			name: "nil map does not panic",
			in:   nil,
			want: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mustRedactor(t, Rules{Headers: tt.extra}).Headers(tt.in)
			if !reflect.DeepEqual(tt.in, tt.want) {
				t.Errorf("got %v, want %v", tt.in, tt.want)
			}
		})
	}
}

// Every default must actually be covered; a typo in the list is a silent leak.
func TestAllDefaultHeadersAreRedacted(t *testing.T) {
	r := Default()
	for _, name := range DefaultHeaders {
		h := map[string][]string{name: {"secret"}}
		r.Headers(h)
		if h[name][0] != Placeholder {
			t.Errorf("default header %q not redacted", name)
		}
	}
}
