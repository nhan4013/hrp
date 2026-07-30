// Package redact removes secrets from recorded interactions.
//
// Redaction runs on the write path only, never on the read path: a cassette gets
// committed to git, and one leaked token stays leaked for the whole of that
// repository's history.
//
// Header redaction needs no configuration. Body redaction does: which JSON field
// holds a card number is application-specific, and a regex broad enough to catch
// every shape of secret would also rewrite ordinary data. What protects an
// unconfigured cassette is `hrp scan`, which looks for secrets that redaction
// missed.
package redact

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"
)

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

// Pattern is a named regular expression whose matches are redacted.
type Pattern struct {
	Name  string
	Regex string
}

// Rules describes what to redact beyond the built-in defaults.
type Rules struct {
	// Headers are redacted in addition to DefaultHeaders.
	Headers []string
	// JSONFields are dotted paths into a JSON body, e.g. "card.number". Arrays
	// along the path are traversed element-wise.
	JSONFields []string
	// Patterns are applied to header values and to body text.
	Patterns []Pattern
}

// Redactor knows what carries secrets.
type Redactor struct {
	headers   map[string]struct{}
	jsonPaths [][]string
	patterns  []*regexp.Regexp
}

// New builds a Redactor. It fails on a regex that does not compile, rather than
// silently dropping the rule that was supposed to protect something.
func New(rules Rules) (*Redactor, error) {
	r := &Redactor{
		headers: make(map[string]struct{}, len(DefaultHeaders)+len(rules.Headers)),
	}
	for _, name := range DefaultHeaders {
		r.headers[name] = struct{}{}
	}
	for _, name := range rules.Headers {
		if name = strings.ToLower(strings.TrimSpace(name)); name != "" {
			r.headers[name] = struct{}{}
		}
	}
	for _, field := range rules.JSONFields {
		path := splitPath(field)
		if len(path) == 0 {
			return nil, fmt.Errorf("redact: empty json_fields entry")
		}
		r.jsonPaths = append(r.jsonPaths, path)
	}
	for _, p := range rules.Patterns {
		re, err := regexp.Compile(p.Regex)
		if err != nil {
			return nil, fmt.Errorf("redact: pattern %q: %w", p.Name, err)
		}
		r.patterns = append(r.patterns, re)
	}
	return r, nil
}

// Default returns a Redactor covering only DefaultHeaders.
func Default() *Redactor {
	r, err := New(Rules{})
	if err != nil {
		panic(err) // Rules{} has no regex to compile, so this cannot fail
	}
	return r
}

// Headers replaces the values of sensitive headers in place, and applies the
// configured patterns to every other header value so that a token in a header
// nobody thought to list is still caught. The number of values is preserved, so
// a cassette still shows that two cookies were sent.
func (r *Redactor) Headers(h map[string][]string) {
	for name, values := range h {
		if _, sensitive := r.headers[strings.ToLower(name)]; sensitive {
			for i := range values {
				values[i] = Placeholder
			}
			continue
		}
		for i, value := range values {
			values[i] = r.applyPatterns(value)
		}
	}
}

// Body returns a redacted copy of raw.
//
// The input is never modified: those exact bytes still have to be forwarded
// upstream. When nothing matches, raw itself comes back, so callers must treat
// the result as read-only.
//
// A JSON body is redacted structurally and re-marshalled. Patterns are applied
// only to its string values, which keeps the result valid JSON — a pattern that
// matched a bare number would otherwise turn `"amount":4111111111111111` into
// `"amount":<REDACTED>` and corrupt the document. The consequence is that a
// secret stored as a JSON *number* is only reachable through JSONFields.
func (r *Redactor) Body(raw []byte) []byte {
	if len(raw) == 0 || (len(r.jsonPaths) == 0 && len(r.patterns) == 0) {
		return raw
	}

	var doc any
	if json.Unmarshal(raw, &doc) == nil {
		changed := false
		for _, path := range r.jsonPaths {
			if replaceAtPath(doc, path) {
				changed = true
			}
		}
		if len(r.patterns) > 0 {
			var patched bool
			doc, patched = r.patternsInStrings(doc)
			changed = changed || patched
		}
		if !changed {
			return raw
		}
		out, err := marshalJSON(doc)
		if err != nil {
			// Cannot happen for a document that just came out of Unmarshal, but
			// keeping the original beats emitting something corrupt.
			return raw
		}
		return out
	}

	if len(r.patterns) > 0 && utf8.Valid(raw) {
		return []byte(r.applyPatterns(string(raw)))
	}
	return raw
}

// marshalJSON re-serializes a redacted document without HTML escaping.
// encoding/json would otherwise turn the placeholder into
// "<REDACTED>", and a cassette exists to be read and reviewed in a
// diff. Encoder appends a newline, which the stored body does not want.
func marshalJSON(doc any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(doc); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

func (r *Redactor) applyPatterns(s string) string {
	for _, re := range r.patterns {
		s = re.ReplaceAllString(s, Placeholder)
	}
	return s
}

// replaceAtPath replaces every value at the given field path. Arrays are
// traversed element-wise, so "items.card" reaches every element of items.
// An explicit null is left alone: reporting it as redacted would be a lie.
func replaceAtPath(node any, path []string) bool {
	switch n := node.(type) {
	case map[string]any:
		value, present := n[path[0]]
		if !present || value == nil {
			return false
		}
		if len(path) == 1 {
			n[path[0]] = Placeholder
			return true
		}
		return replaceAtPath(value, path[1:])
	case []any:
		changed := false
		for _, item := range n {
			if replaceAtPath(item, path) {
				changed = true
			}
		}
		return changed
	}
	return false
}

// patternsInStrings rewrites string values only, leaving numbers and structure
// alone so the document stays valid JSON.
func (r *Redactor) patternsInStrings(node any) (any, bool) {
	switch n := node.(type) {
	case string:
		out := r.applyPatterns(n)
		return out, out != n
	case map[string]any:
		changed := false
		for key, value := range n {
			if replaced, c := r.patternsInStrings(value); c {
				n[key] = replaced
				changed = true
			}
		}
		return n, changed
	case []any:
		changed := false
		for i, value := range n {
			if replaced, c := r.patternsInStrings(value); c {
				n[i] = replaced
				changed = true
			}
		}
		return n, changed
	}
	return node, false
}

func splitPath(field string) []string {
	var path []string
	for _, part := range strings.Split(field, ".") {
		if part = strings.TrimSpace(part); part != "" {
			path = append(path, part)
		}
	}
	return path
}
