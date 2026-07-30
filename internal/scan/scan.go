// Package scan looks for secrets that redaction did not remove.
//
// Redaction is configured; scanning is not. That asymmetry is deliberate: a
// cassette is about to be committed to git, so the last line of defence has to
// work with no configuration at all.
//
// Every built-in detector is high precision. A noisy scanner in a pre-commit
// hook gets switched off, and a switched-off scanner protects nothing. Secrets
// whose only signal is their shape — a 12-digit national ID, a phone number —
// are therefore not built in: they cannot be told apart from a timestamp or an
// order number. Add those as config patterns, which this package picks up.
package scan

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/nhan4013/hrp/internal/cassette"
	"github.com/nhan4013/hrp/internal/redact"
)

// Finding is one suspected secret.
type Finding struct {
	Interaction string
	Location    string
	Detector    string
	// Excerpt is masked: a scan report gets pasted into issues and CI logs, so it
	// must not become a second copy of the secret.
	Excerpt string
}

func (f Finding) String() string {
	return fmt.Sprintf("%s  %s  [%s]  %s", f.Interaction, f.Location, f.Detector, f.Excerpt)
}

type detector struct {
	name string
	re   *regexp.Regexp
	// confirm rejects a match that only looks right. Optional.
	confirm func(string) bool
}

// builtins are ordered most specific first, so a token that matches two
// detectors is reported under the more informative name.
var builtins = []detector{
	{name: "private_key", re: regexp.MustCompile(
		`-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----`)},
	{name: "jwt", re: regexp.MustCompile(
		`\beyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}`)},
	{name: "stripe_key", re: regexp.MustCompile(
		`\b(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{10,}`)},
	{name: "github_token", re: regexp.MustCompile(
		`\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})`)},
	{name: "aws_access_key", re: regexp.MustCompile(`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`)},
	{name: "google_api_key", re: regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{35}\b`)},
	{name: "slack_token", re: regexp.MustCompile(`\bxox[baprs]-[0-9A-Za-z-]{10,}`)},
	{name: "openai_key", re: regexp.MustCompile(`\bsk-[A-Za-z0-9_-]{20,}`)},
	{name: "bearer_token", re: regexp.MustCompile(
		`(?i)\bbearer\s+[A-Za-z0-9._~+/-]{16,}`)},
	{
		name: "card_number",
		re:   regexp.MustCompile(`\b\d(?:[ -]?\d){11,18}\b`),
		// An amount or a timestamp of the same length almost never satisfies
		// Luhn, which is what makes this precise enough to run on every commit.
		confirm: luhnValid,
	},
}

// Scanner holds the detectors to run.
type Scanner struct {
	detectors []detector
}

// New returns a Scanner with the built-in detectors plus one per extra pattern.
// Passing the same patterns used for redaction means anything configured as
// worth hiding is also reported when it slips through.
func New(extra []redact.Pattern) (*Scanner, error) {
	s := &Scanner{detectors: make([]detector, 0, len(builtins)+len(extra))}
	for _, p := range extra {
		re, err := regexp.Compile(p.Regex)
		if err != nil {
			return nil, fmt.Errorf("scan: pattern %q: %w", p.Name, err)
		}
		name := p.Name
		if name == "" {
			name = "config_pattern"
		}
		s.detectors = append(s.detectors, detector{name: name, re: re})
	}
	s.detectors = append(s.detectors, builtins...)
	return s, nil
}

// Interactions scans every recorded request and response.
func (s *Scanner) Interactions(interactions []cassette.Interaction) []Finding {
	var findings []Finding
	for _, in := range interactions {
		findings = append(findings, s.scanRequest(in)...)
		findings = append(findings, s.scanResponse(in)...)
	}
	return findings
}

func (s *Scanner) scanRequest(in cassette.Interaction) []Finding {
	var findings []Finding
	findings = append(findings, s.headers(in.ID, "request", in.Request.Headers)...)

	// Query strings carry api_key=... more often than anyone admits.
	for _, key := range sortedNames(in.Request.Query) {
		for _, value := range in.Request.Query[key] {
			findings = append(findings,
				s.text(in.ID, "request.query."+key, value)...)
		}
	}
	findings = append(findings, s.body(in.ID, "request.body",
		in.Request.Body, in.Request.BodyEncoding)...)
	return findings
}

func (s *Scanner) scanResponse(in cassette.Interaction) []Finding {
	var findings []Finding
	findings = append(findings, s.headers(in.ID, "response", in.Response.Headers)...)
	findings = append(findings, s.body(in.ID, "response.body",
		in.Response.Body, in.Response.BodyEncoding)...)
	return findings
}

func (s *Scanner) headers(id, side string, headers map[string][]string) []Finding {
	var findings []Finding
	for _, name := range sortedNames(headers) {
		for _, value := range headers[name] {
			findings = append(findings, s.text(id, side+".headers."+name, value)...)
		}
	}
	return findings
}

// body decodes before scanning: a base64-stored body that is really UTF-8 text
// would otherwise hide its contents from every detector.
func (s *Scanner) body(id, location, body, encoding string) []Finding {
	if body == "" {
		return nil
	}
	raw, err := cassette.DecodeBody(body, encoding)
	if err != nil {
		return nil
	}
	if !utf8.Valid(raw) {
		return nil
	}
	return s.text(id, location, string(raw))
}

func (s *Scanner) text(id, location, value string) []Finding {
	if value == "" || value == redact.Placeholder {
		return nil
	}
	var findings []Finding
	seen := make(map[string]struct{})
	for _, d := range s.detectors {
		for _, match := range d.re.FindAllString(value, -1) {
			if d.confirm != nil && !d.confirm(match) {
				continue
			}
			if _, dup := seen[match]; dup {
				continue // already reported under a more specific detector
			}
			seen[match] = struct{}{}
			findings = append(findings, Finding{
				Interaction: id,
				Location:    location,
				Detector:    d.name,
				Excerpt:     mask(match),
			})
		}
	}
	return findings
}

// luhnValid reports whether a digit run passes the Luhn checksum, ignoring the
// spaces and dashes people put in card numbers.
func luhnValid(s string) bool {
	sum, double, digits := 0, false, 0
	for i := len(s) - 1; i >= 0; i-- {
		c := s[i]
		if c == ' ' || c == '-' {
			continue
		}
		if c < '0' || c > '9' {
			return false
		}
		d := int(c - '0')
		if double {
			if d *= 2; d > 9 {
				d -= 9
			}
		}
		sum += d
		double = !double
		digits++
	}
	if digits < 12 || digits > 19 {
		return false
	}
	return sum%10 == 0
}

// mask keeps just enough of a match to recognise it without reproducing it.
func mask(s string) string {
	const keepHead, keepTail = 6, 2
	if len(s) <= keepHead+keepTail {
		return strings.Repeat("*", len(s))
	}
	return s[:keepHead] + strings.Repeat("*", 4) + s[len(s)-keepTail:]
}

func sortedNames(m map[string][]string) []string {
	names := make([]string, 0, len(m))
	for name := range m {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
