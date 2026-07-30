// Package matcher decides whether an incoming request matches a recorded one,
// and explains itself when it does not.
//
// Every rule returns a mismatch rather than a bare bool. The worst experience
// this kind of tool can offer is "no match found" and nothing else, so the
// comparison is built to carry the reason all the way out to the developer.
package matcher

import (
	"fmt"
	"strings"

	"github.com/nhan4013/hrp/internal/cassette"
)

// Mismatch describes one aspect of two requests that disagree.
type Mismatch struct {
	Rule     string
	Recorded string
	Incoming string
	// Details holds finer-grained differences, such as the individual JSON
	// fields of a body that do not agree. Optional.
	Details []string
}

// Result is the outcome of comparing an incoming request against a recorded one.
//
// Score is the fraction of rule weight that agreed, so it can rank candidates
// even when none of them match. Method and path carry most of the weight: the
// candidate worth showing a diff against is one that at least addresses the same
// endpoint.
type Result struct {
	Score      float64
	Mismatches []Mismatch
}

// OK reports whether every rule agreed.
func (r Result) OK() bool { return len(r.Mismatches) == 0 }

// Rule compares one aspect of two requests, returning nil when they agree.
type Rule interface {
	Name() string
	Weight() float64
	Compare(recorded, incoming *cassette.Request) *Mismatch
}

// DefaultRules is the rule set used when nothing is configured. Headers are
// deliberately absent: they are noisy, differ per HTTP client, and the ones that
// carry secrets are redacted on both sides anyway. Host is absent too: the
// reverse proxy answers to a single upstream, so the MITM commands opt into it.
var DefaultRules = []string{"method", "path", "query", "body"}

// availableRules is every rule name New accepts, for error messages.
var availableRules = []string{"method", "host", "path", "query", "body"}

// Matcher is a set of rules that must all agree for a request to match.
type Matcher struct {
	rules       []Rule
	totalWeight float64
}

// Option configures a Matcher.
type Option func(*options)

type options struct {
	ignoredQuery []string
}

// IgnoreQuery excludes query parameters from matching, for the timestamps and
// nonces that change on every call.
func IgnoreQuery(keys ...string) Option {
	return func(o *options) { o.ignoredQuery = append(o.ignoredQuery, keys...) }
}

// New builds a Matcher from rule names. An unknown name is an error rather than
// a silent no-op: a typo in a config file must not quietly weaken matching.
func New(names []string, opts ...Option) (*Matcher, error) {
	if len(names) == 0 {
		return nil, fmt.Errorf("matcher: no rules given, want some of %s",
			strings.Join(availableRules, ", "))
	}

	var o options
	for _, apply := range opts {
		apply(&o)
	}

	m := &Matcher{}
	for _, name := range names {
		var rule Rule
		switch strings.ToLower(strings.TrimSpace(name)) {
		case "method":
			rule = methodRule{}
		case "host":
			rule = hostRule{}
		case "path":
			rule = pathRule{}
		case "query":
			rule = newQueryRule(o.ignoredQuery)
		case "body":
			rule = bodyRule{}
		default:
			return nil, fmt.Errorf("matcher: unknown rule %q, want some of %s",
				name, strings.Join(availableRules, ", "))
		}
		m.rules = append(m.rules, rule)
		m.totalWeight += rule.Weight()
	}
	return m, nil
}

// Rules reports the configured rule names, in order.
func (m *Matcher) Rules() []string {
	names := make([]string, len(m.rules))
	for i, r := range m.rules {
		names[i] = r.Name()
	}
	return names
}

// Compare runs every rule against one recorded request.
func (m *Matcher) Compare(recorded, incoming *cassette.Request) Result {
	var agreed float64
	var mismatches []Mismatch
	for _, rule := range m.rules {
		if mm := rule.Compare(recorded, incoming); mm != nil {
			mismatches = append(mismatches, *mm)
			continue
		}
		agreed += rule.Weight()
	}
	return Result{Score: agreed / m.totalWeight, Mismatches: mismatches}
}

// Best returns the index of the candidate that matches incoming most closely,
// together with its comparison result. found is false when there are no
// candidates at all.
//
// The first exact match wins, so re-recording a request that is already present
// cannot shadow the original. Otherwise the highest score wins, and ties go to
// whichever was recorded first.
func (m *Matcher) Best(candidates []cassette.Interaction, incoming *cassette.Request) (index int, res Result, found bool) {
	best, bestRes := -1, Result{Score: -1}
	for i := range candidates {
		r := m.Compare(&candidates[i].Request, incoming)
		if r.OK() {
			return i, r, true
		}
		if r.Score > bestRes.Score {
			best, bestRes = i, r
		}
	}
	if best < 0 {
		return 0, Result{}, false
	}
	return best, bestRes, true
}
