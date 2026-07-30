package redact

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func mustRedactor(t *testing.T, rules Rules) *Redactor {
	t.Helper()
	r, err := New(rules)
	if err != nil {
		t.Fatalf("New(%+v): %v", rules, err)
	}
	return r
}

func TestNewRejectsBadRules(t *testing.T) {
	if _, err := New(Rules{Patterns: []Pattern{{Name: "bad", Regex: `([`}}}); err == nil {
		t.Error("New with an uncompilable regex = nil error, want error")
	}
	if _, err := New(Rules{JSONFields: []string{"."}}); err == nil {
		t.Error("New with an empty json field path = nil error, want error")
	}
}

func TestBodyJSONFields(t *testing.T) {
	tests := []struct {
		name   string
		fields []string
		in     string
		want   string
	}{
		{
			name:   "top level",
			fields: []string{"cvv"},
			in:     `{"cvv":"123","amount":1}`,
			want:   `{"amount":1,"cvv":"<REDACTED>"}`,
		},
		{
			name:   "nested path",
			fields: []string{"card.number"},
			in:     `{"card":{"number":"4111111111111111","brand":"visa"}}`,
			want:   `{"card":{"brand":"visa","number":"<REDACTED>"}}`,
		},
		{
			name:   "numeric value",
			fields: []string{"card.number"},
			in:     `{"card":{"number":4111111111111111}}`,
			want:   `{"card":{"number":"<REDACTED>"}}`,
		},
		{
			name:   "array traversed element-wise",
			fields: []string{"items.token"},
			in:     `{"items":[{"token":"a"},{"token":"b"}]}`,
			want:   `{"items":[{"token":"<REDACTED>"},{"token":"<REDACTED>"}]}`,
		},
		{
			name:   "absent field is a no-op",
			fields: []string{"cvv"},
			in:     `{"amount":1}`,
			want:   `{"amount":1}`,
		},
		{
			name:   "explicit null left alone",
			fields: []string{"cvv"},
			in:     `{"cvv":null}`,
			want:   `{"cvv":null}`,
		},
		{
			name:   "whole object redacted",
			fields: []string{"card"},
			in:     `{"card":{"number":"4111","cvv":"123"}}`,
			want:   `{"card":"<REDACTED>"}`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := mustRedactor(t, Rules{JSONFields: tt.fields})
			got := string(r.Body([]byte(tt.in)))
			if !sameJSON(t, got, tt.want) {
				t.Errorf("Body() = %s, want %s", got, tt.want)
			}
		})
	}
}

// A pattern must not be allowed to turn a JSON document into something that no
// longer parses, which is what replacing a bare number would do.
func TestBodyPatternsKeepJSONValid(t *testing.T) {
	r := mustRedactor(t, Rules{Patterns: []Pattern{
		{Name: "card", Regex: `\b\d{13,19}\b`},
	}})

	in := `{"card":"4111111111111111","amount":1500000000000000}`
	got := r.Body([]byte(in))

	var doc any
	if err := json.Unmarshal(got, &doc); err != nil {
		t.Fatalf("result is not valid JSON: %v\n%s", err, got)
	}
	m := doc.(map[string]any)
	if m["card"] != Placeholder {
		t.Errorf("card = %v, want the placeholder", m["card"])
	}
	// The number keeps its type; only JSONFields can reach a numeric secret.
	if _, isNumber := m["amount"].(float64); !isNumber {
		t.Errorf("amount = %#v, want it left as a number", m["amount"])
	}
}

func TestBodyPatternsOnNonJSON(t *testing.T) {
	r := mustRedactor(t, Rules{Patterns: []Pattern{
		{Name: "token", Regex: `sk_` + `live_[A-Za-z0-9]+`},
	}})

	got := string(r.Body([]byte("key=sk_" + "live_abc123&other=1")))
	if want := "key=<REDACTED>&other=1"; got != want {
		t.Errorf("Body() = %q, want %q", got, want)
	}
}

func TestBodyLeavesBinaryAlone(t *testing.T) {
	r := mustRedactor(t, Rules{Patterns: []Pattern{{Name: "any", Regex: `.`}}})
	in := []byte{0xff, 0xfe, 0x00}
	if got := r.Body(in); !reflect.DeepEqual(got, in) {
		t.Errorf("Body() = %x, want the input unchanged", got)
	}
}

// The original bytes still have to be forwarded upstream, so Body must never
// write through its argument.
func TestBodyDoesNotMutateInput(t *testing.T) {
	r := mustRedactor(t, Rules{
		JSONFields: []string{"cvv"},
		Patterns:   []Pattern{{Name: "digits", Regex: `\d+`}},
	})

	in := []byte(`{"cvv":"123","card":"4111111111111111"}`)
	before := string(in)
	r.Body(in)
	if string(in) != before {
		t.Errorf("input mutated to %s, want %s", in, before)
	}
}

func TestBodyNoRulesIsIdentity(t *testing.T) {
	r := mustRedactor(t, Rules{})
	in := []byte(`{"card":"4111111111111111"}`)
	if got := string(r.Body(in)); got != string(in) {
		t.Errorf("Body() = %s, want it unchanged with no rules", got)
	}
	if got := r.Body(nil); got != nil {
		t.Errorf("Body(nil) = %v, want nil", got)
	}
}

// Redaction has to be idempotent, or a re-record would produce a different body
// than the first run and churn the cassette.
func TestBodyIsIdempotent(t *testing.T) {
	r := mustRedactor(t, Rules{
		JSONFields: []string{"card.number"},
		Patterns:   []Pattern{{Name: "token", Regex: `sk_` + `live_[A-Za-z0-9]+`}},
	})

	once := r.Body([]byte(`{"card":{"number":"4111111111111111"},"key":"sk_` + `live_abc"}`))
	twice := r.Body(once)
	if string(once) != string(twice) {
		t.Errorf("second pass changed the body:\n%s\nvs\n%s", once, twice)
	}
}

// Patterns must reach header values too, so a token in a header nobody listed is
// still caught.
func TestHeadersApplyPatterns(t *testing.T) {
	r := mustRedactor(t, Rules{Patterns: []Pattern{
		{Name: "jwt", Regex: `eyJ[A-Za-z0-9_.-]+`},
	}})

	h := map[string][]string{
		"x-vendor-session": {"eyJhbGciOiJIUzI1NiJ9.abc.def"},
		"content-type":     {"application/json"},
		"authorization":    {"Bearer whatever"},
	}
	r.Headers(h)

	if got := h["x-vendor-session"][0]; got != Placeholder {
		t.Errorf("unlisted header = %q, want the pattern to catch it", got)
	}
	if got := h["content-type"][0]; got != "application/json" {
		t.Errorf("content-type = %q, want it untouched", got)
	}
	if got := h["authorization"][0]; got != Placeholder {
		t.Errorf("authorization = %q, want the placeholder", got)
	}
}

func sameJSON(t *testing.T, a, b string) bool {
	t.Helper()
	var av, bv any
	if err := json.Unmarshal([]byte(a), &av); err != nil {
		return a == b
	}
	if err := json.Unmarshal([]byte(b), &bv); err != nil {
		return a == b
	}
	return reflect.DeepEqual(av, bv)
}

// A cassette exists to be read and reviewed in a diff, so the placeholder must
// not come back as a pile of unicode escapes.
func TestBodyDoesNotHTMLEscape(t *testing.T) {
	r := mustRedactor(t, Rules{JSONFields: []string{"cvv"}})

	got := string(r.Body([]byte(`{"cvv":"123","note":"a < b && c > d"}`)))

	// encoding/json escapes <, > and & by default, which would store the
	// placeholder as \u003cREDACTED\u003e.
	if strings.Contains(got, `\u00`) {
		t.Errorf("body carries unicode escapes: %s", got)
	}
	if !strings.Contains(got, Placeholder) {
		t.Errorf("body = %s, want a readable %s", got, Placeholder)
	}
	if !strings.Contains(got, "a < b && c > d") {
		t.Errorf("body = %s, want the original text preserved", got)
	}
}
