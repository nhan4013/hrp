package cli

import (
	"github.com/nhan4013/hrp/internal/config"
	"github.com/nhan4013/hrp/internal/fault"
	"github.com/nhan4013/hrp/internal/matcher"
	"github.com/nhan4013/hrp/internal/redact"
	"github.com/nhan4013/hrp/internal/scan"
)

// This file turns config data into the objects the rest of the program uses.
// config stays a plain data package, and nothing else has to know the YAML shape.

func buildRedactor(c *config.Config) (*redact.Redactor, error) {
	if c == nil {
		return redact.Default(), nil
	}
	return redact.New(redact.Rules{
		Headers:    c.Redact.Headers,
		JSONFields: c.Redact.JSONFields,
		Patterns:   redactPatterns(c),
	})
}

func buildMatcher(c *config.Config, extraIgnoreQuery []string) (*matcher.Matcher, error) {
	rules := matcher.DefaultRules
	var ignoreQuery []string
	if c != nil {
		if len(c.Match.On) > 0 {
			rules = c.Match.On
		}
		ignoreQuery = c.Match.IgnoreQuery
	}
	ignoreQuery = append(ignoreQuery, extraIgnoreQuery...)

	var opts []matcher.Option
	if len(ignoreQuery) > 0 {
		opts = append(opts, matcher.IgnoreQuery(ignoreQuery...))
	}
	return matcher.New(rules, opts...)
}

// buildFault returns nil when no config asks for faults, which leaves the
// middleware out of the chain entirely.
func buildFault(c *config.Config) (*fault.Injector, error) {
	if c == nil || !c.Fault.Enabled {
		return nil, nil
	}
	return fault.New(fault.Config{
		Latency:     c.Fault.Latency,
		ErrorRate:   c.Fault.ErrorRate,
		ErrorStatus: c.Fault.ErrorStatus,
		HangRate:    c.Fault.HangRate,
		Seed:        c.Fault.Seed,
	})
}

func buildScanner(c *config.Config) (*scan.Scanner, error) {
	return scan.New(redactPatterns(c))
}

// redactPatterns converts config patterns once, so the redactor and the scanner
// are guaranteed to be looking for the same things.
func redactPatterns(c *config.Config) []redact.Pattern {
	if c == nil {
		return nil
	}
	out := make([]redact.Pattern, 0, len(c.Redact.Patterns))
	for _, p := range c.Redact.Patterns {
		out = append(out, redact.Pattern{Name: p.Name, Regex: p.Regex})
	}
	return out
}
