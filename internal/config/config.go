// Package config parses hrp.yaml.
//
// It only holds and validates data. Turning that data into a matcher, a redactor
// and a fault injector is the CLI's job, which keeps this package free of
// dependencies on any of them.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the whole of hrp.yaml.
//
// There is deliberately no `mode` key: the subcommand is the mode, and having
// two places to say it invites them to disagree. There is no `ignore_headers`
// key either — headers take no part in matching, and the ones that would create
// diff noise are already dropped when recording.
type Config struct {
	Listen   string `yaml:"listen"`
	Upstream string `yaml:"upstream"`
	Cassette string `yaml:"cassette"`
	Match    Match  `yaml:"match"`
	Redact   Redact `yaml:"redact"`
	Fault    Fault  `yaml:"fault"`
}

// Match controls which parts of a request have to agree.
type Match struct {
	On          []string `yaml:"on"`
	IgnoreQuery []string `yaml:"ignore_query"`
}

// Redact controls what is removed before anything is written to disk.
type Redact struct {
	Headers    []string  `yaml:"headers"`
	JSONFields []string  `yaml:"json_fields"`
	Patterns   []Pattern `yaml:"patterns"`
}

// Pattern is a named regular expression.
type Pattern struct {
	Name  string `yaml:"name"`
	Regex string `yaml:"regex"`
}

// Fault controls injected failures.
type Fault struct {
	Enabled     bool          `yaml:"enabled"`
	Latency     time.Duration `yaml:"latency"`
	ErrorRate   float64       `yaml:"error_rate"`
	ErrorStatus int           `yaml:"error_status"`
	HangRate    float64       `yaml:"hang_rate"`
	Seed        int64         `yaml:"seed"`
}

// Load reads and validates a config file.
func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}
	return parse(raw, path)
}

func parse(raw []byte, path string) (*Config, error) {
	var cfg Config

	dec := yaml.NewDecoder(bytes.NewReader(raw))
	// Reject unknown keys. A misspelled redact rule that silently does nothing is
	// exactly the failure this file exists to prevent.
	dec.KnownFields(true)

	// A file that is empty or all comments decodes to EOF. That is a valid config
	// where every setting takes its default, not a parse failure.
	if err := dec.Decode(&cfg); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}

	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("config %s: %w", path, err)
	}
	return &cfg, nil
}

func (c *Config) validate() error {
	for i, p := range c.Redact.Patterns {
		if p.Regex == "" {
			return fmt.Errorf("redact.patterns[%d] (%q) has no regex", i, p.Name)
		}
	}
	for i, field := range c.Redact.JSONFields {
		if field == "" {
			return fmt.Errorf("redact.json_fields[%d] is empty", i)
		}
	}
	// Rates and statuses are checked again by the fault package; catching them
	// here names the config key rather than an internal field.
	if c.Fault.Latency < 0 {
		return fmt.Errorf("fault.latency %s is negative", c.Fault.Latency)
	}
	if r := c.Fault.ErrorRate; r < 0 || r > 1 {
		return fmt.Errorf("fault.error_rate %v is outside 0..1", r)
	}
	if r := c.Fault.HangRate; r < 0 || r > 1 {
		return fmt.Errorf("fault.hang_rate %v is outside 0..1", r)
	}
	if s := c.Fault.ErrorStatus; s != 0 && (s < 100 || s > 599) {
		return fmt.Errorf("fault.error_status %d is not a valid HTTP status", s)
	}
	return nil
}
