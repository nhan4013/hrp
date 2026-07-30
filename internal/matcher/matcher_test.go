package matcher

import (
	"net/http"
	"strings"
	"testing"

	"github.com/nhan4013/hrp/internal/cassette"
)

func req(method, path, body string, query map[string][]string) cassette.Request {
	r := cassette.Request{
		Method:   method,
		Path:     path,
		Query:    query,
		Body:     body,
		BodyHash: cassette.HashBody([]byte(body)),
	}
	return r
}

func mustNew(t *testing.T, names []string, opts ...Option) *Matcher {
	t.Helper()
	m, err := New(names, opts...)
	if err != nil {
		t.Fatalf("New(%v): %v", names, err)
	}
	return m
}

func TestNewRejectsBadRuleSets(t *testing.T) {
	if _, err := New(nil); err == nil {
		t.Error("New(nil) = nil error, want error")
	}
	if _, err := New([]string{"method", "headders"}); err == nil {
		t.Error("New with typo'd rule = nil error, want error: a typo must not weaken matching")
	}
}

func TestNewAcceptsDefaultRules(t *testing.T) {
	m := mustNew(t, DefaultRules)
	if got := strings.Join(m.Rules(), ","); got != "method,path,query,body" {
		t.Errorf("Rules = %q", got)
	}
}

// JSON key order must not decide a match, but values must.
func TestBodyRule(t *testing.T) {
	tests := []struct {
		name      string
		recorded  string
		incoming  string
		wantMatch bool
	}{
		{"identical", `{"a":1}`, `{"a":1}`, true},
		{"key order", `{"a":1,"b":2}`, `{"b":2,"a":1}`, true},
		{"whitespace", `{"a": 1}`, `{"a":1}`, true},
		{"nested key order", `{"o":{"x":1,"y":2}}`, `{"o":{"y":2,"x":1}}`, true},
		{"int vs float form", `{"a":1}`, `{"a":1.0}`, true},
		{"different value", `{"a":1}`, `{"a":2}`, false},
		{"missing field", `{"a":1,"b":2}`, `{"a":1}`, false},
		{"extra field", `{"a":1}`, `{"a":1,"b":2}`, false},
		{"array order matters", `{"a":[1,2]}`, `{"a":[2,1]}`, false},
		{"empty both", ``, ``, true},
		{"empty vs non-empty", ``, `{"a":1}`, false},
		{"non-json identical", `plain text`, `plain text`, true},
		{"non-json different", `plain text`, `other text`, false},
	}
	rule := bodyRule{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := req(http.MethodPost, "/x", tt.recorded, nil)
			in := req(http.MethodPost, "/x", tt.incoming, nil)
			mm := rule.Compare(&rec, &in)
			if got := mm == nil; got != tt.wantMatch {
				t.Errorf("match = %v, want %v (mismatch=%+v)", got, tt.wantMatch, mm)
			}
		})
	}
}

func TestMethodRuleIsCaseInsensitive(t *testing.T) {
	rec := req("post", "/x", "", nil)
	in := req("POST", "/x", "", nil)
	if mm := (methodRule{}).Compare(&rec, &in); mm != nil {
		t.Errorf("method compare = %+v, want match", mm)
	}
}

func TestPathRuleIsExact(t *testing.T) {
	rec := req(http.MethodGet, "/v1/charges", "", nil)
	for _, path := range []string{"/v1/charges/", "/V1/charges", "/v1/refunds"} {
		in := req(http.MethodGet, path, "", nil)
		if mm := (pathRule{}).Compare(&rec, &in); mm == nil {
			t.Errorf("path %q matched /v1/charges, want mismatch", path)
		}
	}
}

func TestQueryRuleIgnoresConfiguredKeys(t *testing.T) {
	m := mustNew(t, []string{"query"}, IgnoreQuery("timestamp", "Nonce"))

	rec := req(http.MethodGet, "/x", "", map[string][]string{
		"currency": {"VND"}, "timestamp": {"111"}, "nonce": {"a"},
	})
	in := req(http.MethodGet, "/x", "", map[string][]string{
		"currency": {"VND"}, "timestamp": {"999"}, "nonce": {"b"},
	})
	if res := m.Compare(&rec, &in); !res.OK() {
		t.Errorf("ignored query keys still caused a mismatch: %+v", res.Mismatches)
	}

	in.Query["currency"] = []string{"USD"}
	res := m.Compare(&rec, &in)
	if res.OK() {
		t.Fatal("differing currency matched, want mismatch")
	}
	if got := res.Mismatches[0].Details; len(got) != 1 ||
		!strings.Contains(got[0], "currency") {
		t.Errorf("query details = %v, want one entry naming currency", got)
	}
}

// Score must rank a same-endpoint candidate above a different-endpoint one, so
// the diff shown to the developer is the useful one.
func TestScoreRanksSameEndpointHigher(t *testing.T) {
	m := mustNew(t, DefaultRules)
	in := req(http.MethodPost, "/v1/charges", `{"amount":2}`, nil)

	sameEndpoint := req(http.MethodPost, "/v1/charges", `{"amount":1}`, nil)
	otherPath := req(http.MethodPost, "/v1/refunds", `{"amount":2}`, nil)
	otherMethod := req(http.MethodGet, "/v1/charges", `{"amount":2}`, nil)

	same := m.Compare(&sameEndpoint, &in).Score
	path := m.Compare(&otherPath, &in).Score
	method := m.Compare(&otherMethod, &in).Score

	if same <= path || same <= method {
		t.Errorf("same-endpoint score %.2f must beat path %.2f and method %.2f",
			same, path, method)
	}
}

func TestCompareExactMatchScoresOne(t *testing.T) {
	m := mustNew(t, DefaultRules)
	r := req(http.MethodPost, "/v1/charges", `{"amount":1}`,
		map[string][]string{"currency": {"VND"}})
	res := m.Compare(&r, &r)
	if !res.OK() || res.Score != 1 {
		t.Errorf("identical requests: OK=%v score=%.2f, want true and 1.00", res.OK(), res.Score)
	}
}

func TestBestPicksExactMatchOverCloserScore(t *testing.T) {
	m := mustNew(t, DefaultRules)
	candidates := []cassette.Interaction{
		{ID: "near", Request: req(http.MethodPost, "/v1/charges", `{"amount":1}`, nil)},
		{ID: "exact", Request: req(http.MethodPost, "/v1/charges", `{"amount":2}`, nil)},
	}
	in := req(http.MethodPost, "/v1/charges", `{"amount":2}`, nil)

	index, res, found := m.Best(candidates, &in)
	if !found || !res.OK() {
		t.Fatalf("found=%v OK=%v, want an exact match", found, res.OK())
	}
	if candidates[index].ID != "exact" {
		t.Errorf("Best picked %q, want exact", candidates[index].ID)
	}
}

func TestBestReturnsClosestOnMiss(t *testing.T) {
	m := mustNew(t, DefaultRules)
	candidates := []cassette.Interaction{
		{ID: "wrong-path", Request: req(http.MethodPost, "/v1/refunds", `{"amount":2}`, nil)},
		{ID: "same-path", Request: req(http.MethodPost, "/v1/charges", `{"amount":1}`, nil)},
	}
	in := req(http.MethodPost, "/v1/charges", `{"amount":2}`, nil)

	index, res, found := m.Best(candidates, &in)
	if !found {
		t.Fatal("found = false, want the closest candidate")
	}
	if res.OK() {
		t.Fatal("res.OK() = true, want a miss")
	}
	if candidates[index].ID != "same-path" {
		t.Errorf("closest = %q, want same-path", candidates[index].ID)
	}
	if len(res.Mismatches) != 1 || res.Mismatches[0].Rule != "body" {
		t.Errorf("mismatches = %+v, want exactly the body rule", res.Mismatches)
	}
}

func TestBestOnEmptyCassette(t *testing.T) {
	m := mustNew(t, DefaultRules)
	in := req(http.MethodGet, "/x", "", nil)
	if _, _, found := m.Best(nil, &in); found {
		t.Error("found = true on an empty cassette, want false")
	}
}
