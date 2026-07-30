package matcher

import (
	"flag"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/nhan4013/hrp/internal/cassette"
)

// update regenerates the golden files: go test ./internal/matcher -update
//
// The miss report is the one piece of output a developer reads when things go
// wrong, and it is assembled from several pieces. Asserting on substrings misses
// layout regressions; a golden file catches the whole thing.
var update = flag.Bool("update", false, "update golden files")

func TestGoldenMissReport(t *testing.T) {
	cases := []struct {
		name       string
		golden     string
		candidates []cassette.Interaction
		incoming   cassette.Request
	}{
		{
			name:   "body differs",
			golden: "testdata/golden/miss_body.txt",
			candidates: []cassette.Interaction{{
				ID: "3992f97c9faf",
				Request: req(http.MethodPost, "/v1/charges",
					`{"amount":1500000,"currency":"VND","card":{"last4":"1111"}}`,
					map[string][]string{"currency": {"VND"}}),
			}},
			incoming: req(http.MethodPost, "/v1/charges",
				`{"amount":2000000,"currency":"VND","card":{"last4":"4242"}}`,
				map[string][]string{"currency": {"VND"}}),
		},
		{
			name:   "path and query differ",
			golden: "testdata/golden/miss_path.txt",
			candidates: []cassette.Interaction{{
				ID:      "8fa13f7c4e58",
				Request: req(http.MethodGet, "/v1/charges", "", map[string][]string{"limit": {"10"}}),
			}},
			incoming: req(http.MethodGet, "/v1/refunds", "", map[string][]string{"limit": {"25"}}),
		},
		{
			name:     "empty cassette",
			golden:   "testdata/golden/miss_empty.txt",
			incoming: req(http.MethodGet, "/v1/charges", "", nil),
		},
	}

	m := mustNew(t, DefaultRules)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var best *cassette.Interaction
			var res Result
			if index, r, found := m.Best(tc.candidates, &tc.incoming); found {
				best, res = &tc.candidates[index], r
			}
			compareGolden(t, tc.golden, []byte(Explain(&tc.incoming, best, res)))
		})
	}
}

func compareGolden(t *testing.T, path string, got []byte) {
	t.Helper()

	if *update {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("updated %s", path)
		return
	}

	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden %s: %v\nrun: go test ./internal/matcher -update", path, err)
	}
	if string(got) != string(want) {
		t.Errorf("%s is out of date.\n\n--- want ---\n%s\n--- got ---\n%s\n\n"+
			"If the change is intended, re-run with -update and review the diff.",
			path, want, got)
	}
}
