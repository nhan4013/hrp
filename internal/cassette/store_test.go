package cassette

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func interaction(id string) Interaction {
	return Interaction{
		ID:       id,
		Request:  Request{Method: http.MethodGet, Path: "/" + id},
		Response: Response{Status: 200},
	}
}

func TestLoadMissingFileStartsEmpty(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "new.yaml")
	s, err := Load(path, "payments", "https://vendor.com")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if s.Len() != 0 {
		t.Errorf("Len = %d, want 0", s.Len())
	}
}

func TestLoadRejectsUnknownVersion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "c.yaml")
	if err := os.WriteFile(path, []byte("version: 99\nname: x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path, "", ""); err == nil {
		t.Error("Load with version 99 = nil error, want error")
	}
}

func TestLoadRejectsGarbage(t *testing.T) {
	path := filepath.Join(t.TempDir(), "c.yaml")
	if err := os.WriteFile(path, []byte("::: not yaml :::\n\tbad"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path, "", ""); err == nil {
		t.Error("Load with garbage = nil error, want error")
	}
}

// Recording the same traffic twice must not grow the cassette.
func TestAppendDedupsByID(t *testing.T) {
	s, err := Load(filepath.Join(t.TempDir(), "c.yaml"), "x", "y")
	if err != nil {
		t.Fatal(err)
	}
	s.Append(interaction("a"))
	s.Append(interaction("b"))
	s.Append(interaction("a"))

	if s.Len() != 2 {
		t.Errorf("Len = %d, want 2", s.Len())
	}
}

func TestFlushThenLoadRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "c.yaml")
	s, err := Load(path, "payments", "https://vendor.com")
	if err != nil {
		t.Fatal(err)
	}
	in := interaction("abc123")
	in.Request.Body = `{"amount":1}`
	in.Request.Headers = map[string][]string{"authorization": {"<REDACTED>"}}
	in.Response.Body = `{"id":"ch_1"}`
	s.Append(in)

	if err := s.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}

	reloaded, err := Load(path, "", "")
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if reloaded.Len() != 1 {
		t.Fatalf("reloaded Len = %d, want 1", reloaded.Len())
	}
	got := reloaded.cassette.Interactions[0]
	if got.ID != "abc123" || got.Request.Body != `{"amount":1}` || got.Response.Body != `{"id":"ch_1"}` {
		t.Errorf("reloaded interaction = %+v", got)
	}
	if reloaded.cassette.Name != "payments" || reloaded.cassette.Upstream != "https://vendor.com" {
		t.Errorf("metadata lost: name=%q upstream=%q",
			reloaded.cassette.Name, reloaded.cassette.Upstream)
	}

	// Dedup must survive a reload, so a second record run is idempotent.
	reloaded.Append(interaction("abc123"))
	if reloaded.Len() != 1 {
		t.Errorf("after reload Append of known ID, Len = %d, want 1", reloaded.Len())
	}
}

// A flush with nothing new must not rewrite the file, so a replay-only run
// leaves the cassette untouched in git.
func TestFlushSkipsWhenClean(t *testing.T) {
	path := filepath.Join(t.TempDir(), "c.yaml")
	s, err := Load(path, "x", "y")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("clean Flush created the file, want no write")
	}

	s.Append(interaction("a"))
	if err := s.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat after dirty flush: %v", err)
	}

	if err := s.Flush(); err != nil {
		t.Fatalf("second Flush: %v", err)
	}
	again, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !info.ModTime().Equal(again.ModTime()) {
		t.Error("clean Flush rewrote the file")
	}
}

// Flush must leave no temp files behind: the cassette directory gets committed.
func TestFlushLeavesNoTempFiles(t *testing.T) {
	dir := t.TempDir()
	s, err := Load(filepath.Join(dir, "c.yaml"), "x", "y")
	if err != nil {
		t.Fatal(err)
	}
	s.Append(interaction("a"))
	if err := s.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "c.yaml" {
		names := make([]string, len(entries))
		for i, e := range entries {
			names[i] = e.Name()
		}
		t.Errorf("dir contains %v, want only c.yaml", names)
	}
}

// Run with -race: many goroutines appending while others read and flush.
func TestConcurrentAppendAndFlush(t *testing.T) {
	path := filepath.Join(t.TempDir(), "c.yaml")
	s, err := Load(path, "x", "y")
	if err != nil {
		t.Fatal(err)
	}

	const writers = 100
	var wg sync.WaitGroup
	wg.Add(writers)
	for i := 0; i < writers; i++ {
		go func(i int) {
			defer wg.Done()
			s.Append(interaction(fmt.Sprintf("id-%d", i)))
			s.Len()
			if err := s.Flush(); err != nil {
				t.Errorf("concurrent Flush: %v", err)
			}
		}(i)
	}
	wg.Wait()

	if s.Len() != writers {
		t.Errorf("Len = %d, want %d", s.Len(), writers)
	}
	reloaded, err := Load(path, "", "")
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if reloaded.Len() != writers {
		t.Errorf("reloaded Len = %d, want %d", reloaded.Len(), writers)
	}
}
