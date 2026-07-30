// Package redact removes secrets from recorded interactions.
//
// Redaction runs on the write path only, never on the read path: a cassette
// gets committed to git, and one leaked token stays leaked for the whole of that
// repository's history.
package redact

import "strings"

// Placeholder replaces every redacted value.
const Placeholder = "<REDACTED>"

// DefaultHeaders are redacted with no configuration required. Opting out has to
// be a deliberate act, not the consequence of forgetting to write a config file.
var DefaultHeaders = []string{
	"authorization",
	"proxy-authorization",
	"cookie",
	"set-cookie",
	"x-api-key",
	"api-key",
	"x-auth-token",
	"x-amz-security-token",
}

// Redactor knows which header names carry secrets.
type Redactor struct {
	headers map[string]struct{}
}

// New returns a Redactor covering DefaultHeaders plus extra. Header names match
// case-insensitively.
func New(extra ...string) *Redactor {
	r := &Redactor{headers: make(map[string]struct{}, len(DefaultHeaders)+len(extra))}
	for _, name := range DefaultHeaders {
		r.headers[strings.ToLower(name)] = struct{}{}
	}
	for _, name := range extra {
		if name = strings.ToLower(strings.TrimSpace(name)); name != "" {
			r.headers[name] = struct{}{}
		}
	}
	return r
}

// Headers replaces the values of sensitive headers in place. The number of
// values is preserved, so a cassette still shows that two cookies were sent.
func (r *Redactor) Headers(h map[string][]string) {
	for name, values := range h {
		if _, sensitive := r.headers[strings.ToLower(name)]; !sensitive {
			continue
		}
		for i := range values {
			values[i] = Placeholder
		}
	}
}
