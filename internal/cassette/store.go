package cassette

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

// Store holds a cassette in memory and persists it to disk. Replay reads far
// more often than record writes, so access is guarded by an RWMutex.
type Store struct {
	path string

	mu       sync.RWMutex
	cassette *Cassette
	seen     map[string]struct{}
	dirty    bool
}

// Load reads the cassette at path, or starts an empty one when the file does
// not exist yet. name and upstream are used only for a freshly created cassette.
func Load(path, name, upstream string) (*Store, error) {
	raw, err := os.ReadFile(path)
	switch {
	case err == nil:
	case errors.Is(err, os.ErrNotExist):
		return newStore(path, &Cassette{
			Version:    Version,
			Name:       name,
			Upstream:   upstream,
			RecordedAt: time.Now(),
		}), nil
	default:
		return nil, fmt.Errorf("read cassette %s: %w", path, err)
	}

	var c Cassette
	if err := yaml.Unmarshal(raw, &c); err != nil {
		return nil, fmt.Errorf("parse cassette %s: %w", path, err)
	}
	if c.Version != Version {
		return nil, fmt.Errorf("cassette %s: format version %d, this build understands %d",
			path, c.Version, Version)
	}
	return newStore(path, &c), nil
}

func newStore(path string, c *Cassette) *Store {
	s := &Store{
		path:     path,
		cassette: c,
		seen:     make(map[string]struct{}, len(c.Interactions)),
	}
	for _, in := range c.Interactions {
		s.seen[in.ID] = struct{}{}
	}
	return s
}

// Append records an interaction. Re-recording a request that is already in the
// cassette is a no-op, so running record twice does not grow the file.
//
// ponytail: dedup is by request ID, so a request that legitimately returns
// different responses over time keeps only the first. Add a sequence suffix to
// the ID if state-machine recording is ever needed.
func (s *Store) Append(in Interaction) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.seen[in.ID]; ok {
		return
	}
	s.seen[in.ID] = struct{}{}
	s.cassette.Interactions = append(s.cassette.Interactions, in)
	s.dirty = true
}

// Len reports how many interactions the cassette holds.
func (s *Store) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.cassette.Interactions)
}

// MarkHit counts a replay of the given interaction.
//
// This deliberately does not mark the store dirty. Hit counts are useful within
// a run, but persisting them would rewrite the cassette on every replay-only
// run and turn a passing test suite into a dirty working tree.
func (s *Store) MarkHit(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.cassette.Interactions {
		if s.cassette.Interactions[i].ID == id {
			s.cassette.Interactions[i].Meta.HitCount++
			return
		}
	}
}

// Interactions returns the recorded interactions. The slice is a copy, so
// callers can iterate it without holding the lock.
//
// ponytail: this copies the slice header and struct values on every replay
// lookup. Fine for the hundreds of interactions a cassette normally holds; if
// cassettes grow to tens of thousands, index by method+path instead.
func (s *Store) Interactions() []Interaction {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]Interaction(nil), s.cassette.Interactions...)
}

// Flush writes the cassette to disk if it changed since the last flush. The
// write lands in a temporary file and is renamed into place, so an interrupt
// mid-write cannot leave a truncated cassette behind.
func (s *Store) Flush() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.dirty {
		return nil
	}

	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create cassette dir %s: %w", dir, err)
	}
	out, err := yaml.Marshal(s.cassette)
	if err != nil {
		return fmt.Errorf("marshal cassette: %w", err)
	}

	tmp, err := os.CreateTemp(dir, filepath.Base(s.path)+".tmp*")
	if err != nil {
		return fmt.Errorf("create temp cassette: %w", err)
	}
	defer func() { _ = os.Remove(tmp.Name()) }()

	if _, err := tmp.Write(out); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write temp cassette: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp cassette: %w", err)
	}
	if err := os.Rename(tmp.Name(), s.path); err != nil {
		return fmt.Errorf("rename cassette into place: %w", err)
	}

	s.dirty = false
	return nil
}
