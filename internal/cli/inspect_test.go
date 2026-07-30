package cli

import (
	"encoding/base64"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nhan4013/hrp/internal/cassette"
)

func storeWith(t *testing.T, interactions ...cassette.Interaction) *cassette.Store {
	t.Helper()
	store, err := cassette.Load(filepath.Join(t.TempDir(), "c.yaml"), "payments", "https://vendor.com")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	for _, in := range interactions {
		store.Append(in)
	}
	return store
}

func TestInspectTable(t *testing.T) {
	store := storeWith(t,
		cassette.Interaction{
			ID: "aaa111",
			Request: cassette.Request{
				Method: http.MethodPost,
				Path:   "/v1/charges",
				Query:  map[string][]string{"currency": {"VND"}},
				Body:   `{"amount":1}`,
			},
			Response: cassette.Response{Status: 201, Body: `{"id":"ch_1"}`, DurationMS: 342},
			Meta:     cassette.Meta{HitCount: 3},
		},
		cassette.Interaction{
			ID:       "bbb222",
			Request:  cassette.Request{Method: http.MethodGet, Path: "/v1/ping"},
			Response: cassette.Response{Status: 200},
		},
	)

	var out strings.Builder
	if err := writeInspectTable(&out, "c.yaml", store, "recorded"); err != nil {
		t.Fatalf("writeInspectTable: %v", err)
	}
	got := out.String()

	for _, want := range []string{
		"2 interaction(s)",
		"ID", "METHOD", "PATH", "QUERY", "STATUS", "REQ", "RESP", "MS", "HITS",
		"aaa111", "POST", "/v1/charges", "currency=VND", "201", "12B", "13B", "342", "3",
		"bbb222", "GET", "/v1/ping", "200",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("table missing %q:\n%s", want, got)
		}
	}
	// An absent body and query must read as a dash, not as an empty column.
	if !strings.Contains(got, "-") {
		t.Errorf("table should use - for absent values:\n%s", got)
	}
}

// A forward-proxy cassette spans upstreams, so the table gains a HOST column.
// A reverse-proxy cassette has one upstream for the whole file: no column.
func TestInspectShowsHostWhenRecorded(t *testing.T) {
	store := storeWith(t, cassette.Interaction{
		ID: "aaa111",
		Request: cassette.Request{
			Scheme: "https",
			Host:   "api.vendor.com",
			Method: http.MethodGet,
			Path:   "/v1/ping",
		},
		Response: cassette.Response{Status: 200},
	})

	var out strings.Builder
	if err := writeInspectTable(&out, "c.yaml", store, "recorded"); err != nil {
		t.Fatalf("writeInspectTable: %v", err)
	}
	got := out.String()
	if !strings.Contains(got, "HOST") {
		t.Errorf("table should have a HOST column:\n%s", got)
	}
	if !strings.Contains(got, "https://api.vendor.com") {
		t.Errorf("table should show scheme://host:\n%s", got)
	}
}

func TestInspectOmitsHostWhenAbsent(t *testing.T) {
	store := storeWith(t, cassette.Interaction{
		ID:       "aaa111",
		Request:  cassette.Request{Method: http.MethodGet, Path: "/v1/ping"},
		Response: cassette.Response{Status: 200},
	})

	var out strings.Builder
	if err := writeInspectTable(&out, "c.yaml", store, "recorded"); err != nil {
		t.Fatalf("writeInspectTable: %v", err)
	}
	if got := out.String(); strings.Contains(got, "HOST") {
		t.Errorf("reverse-proxy cassette should not grow a HOST column:\n%s", got)
	}
}

func TestInspectEmptyCassette(t *testing.T) {
	var out strings.Builder
	if err := writeInspectTable(&out, "c.yaml", storeWith(t), "recorded"); err != nil {
		t.Fatalf("writeInspectTable: %v", err)
	}
	if got := out.String(); !strings.Contains(got, "empty") {
		t.Errorf("output should say the cassette is empty:\n%s", got)
	}
}

// Sizes must describe the original payload; base64 storage inflates by a third
// and would make a recorded body look bigger than it was.
func TestInspectReportsDecodedBodySize(t *testing.T) {
	raw := []byte{0x1f, 0x8b, 0x08, 0x00, 0xff}
	store := storeWith(t, cassette.Interaction{
		ID:      "bin",
		Request: cassette.Request{Method: http.MethodGet, Path: "/blob"},
		Response: cassette.Response{
			Status:       200,
			Body:         base64.StdEncoding.EncodeToString(raw),
			BodyEncoding: cassette.EncodingBase64,
		},
	})

	var out strings.Builder
	if err := writeInspectTable(&out, "c.yaml", store, "recorded"); err != nil {
		t.Fatal(err)
	}
	if got := out.String(); !strings.Contains(got, "5B") {
		t.Errorf("want the decoded size 5B, got:\n%s", got)
	}
}

func TestInspectSortOrders(t *testing.T) {
	store := storeWith(t,
		cassette.Interaction{
			ID:       "z",
			Request:  cassette.Request{Method: http.MethodGet, Path: "/zebra"},
			Response: cassette.Response{Status: 500},
		},
		cassette.Interaction{
			ID:       "a",
			Request:  cassette.Request{Method: http.MethodGet, Path: "/apple"},
			Response: cassette.Response{Status: 200},
		},
	)

	tests := []struct {
		sortBy string
		first  string
	}{
		{"recorded", "/zebra"},
		{"path", "/apple"},
		{"status", "/apple"},
	}
	for _, tt := range tests {
		t.Run(tt.sortBy, func(t *testing.T) {
			var out strings.Builder
			if err := writeInspectTable(&out, "c.yaml", store, tt.sortBy); err != nil {
				t.Fatalf("writeInspectTable: %v", err)
			}
			var dataRows []string
			for _, line := range strings.Split(strings.TrimSpace(out.String()), "\n") {
				if strings.HasPrefix(line, "z ") || strings.HasPrefix(line, "a ") {
					dataRows = append(dataRows, line)
				}
			}
			if len(dataRows) != 2 {
				t.Fatalf("expected 2 data rows, got %v", dataRows)
			}
			if !strings.Contains(dataRows[0], tt.first) {
				t.Errorf("--sort %s put %q first, want %q", tt.sortBy, dataRows[0], tt.first)
			}
		})
	}
}

// Sorting must not reorder the store itself; inspect is read-only.
func TestInspectDoesNotReorderTheStore(t *testing.T) {
	store := storeWith(t,
		cassette.Interaction{ID: "z", Request: cassette.Request{Method: "GET", Path: "/zebra"}},
		cassette.Interaction{ID: "a", Request: cassette.Request{Method: "GET", Path: "/apple"}},
	)

	var out strings.Builder
	if err := writeInspectTable(&out, "c.yaml", store, "path"); err != nil {
		t.Fatal(err)
	}
	if got := store.Interactions()[0].ID; got != "z" {
		t.Errorf("store reordered: first ID = %q, want z", got)
	}
}

func TestInspectRejectsUnknownSort(t *testing.T) {
	var out strings.Builder
	if err := writeInspectTable(&out, "c.yaml", storeWith(t), "duration"); err == nil {
		t.Error("unknown --sort = nil error, want error")
	}
}
