package matcher

import (
	"net/http"
	"strings"
	"testing"

	"github.com/nhan4013/hrp/internal/cassette"
)

// The report has to name the endpoint, the closest candidate, the failing rule
// and the actual difference. "No match found" and nothing else is the failure
// mode this whole design exists to avoid.
func TestExplainNamesTheActualDifference(t *testing.T) {
	m := mustNew(t, DefaultRules)
	recorded := req(http.MethodPost, "/v1/charges", `{"amount":1500000,"currency":"VND"}`, nil)
	incoming := req(http.MethodPost, "/v1/charges", `{"amount":2000000,"currency":"VND"}`, nil)
	best := &cassette.Interaction{ID: "01J8K", Request: recorded}

	report := Explain(&incoming, best, m.Compare(&recorded, &incoming))

	for _, want := range []string{
		"POST /v1/charges",
		"Closest candidate: 01J8K",
		"Differs on: body",
		"- recorded:",
		"+ incoming:",
		"amount: recorded 1500000, incoming 2000000",
	} {
		if !strings.Contains(report, want) {
			t.Errorf("report missing %q:\n%s", want, report)
		}
	}
	// The field that agreed must not be listed as a difference.
	if strings.Contains(report, "currency: recorded") {
		t.Errorf("report lists matching field currency as a difference:\n%s", report)
	}
}

func TestExplainOnEmptyCassette(t *testing.T) {
	incoming := req(http.MethodGet, "/v1/charges", "", nil)
	report := Explain(&incoming, nil, Result{})
	if !strings.Contains(report, "no interactions") {
		t.Errorf("report should say the cassette is empty:\n%s", report)
	}
}

// A 10 MiB body must not be dumped into an error response.
func TestExplainTruncatesHugeValues(t *testing.T) {
	huge := strings.Repeat("x", 50_000)
	recorded := req(http.MethodPost, "/upload", huge, nil)
	incoming := req(http.MethodPost, "/upload", strings.Repeat("y", 50_000), nil)
	m := mustNew(t, DefaultRules)

	report := Explain(&incoming, &cassette.Interaction{ID: "big", Request: recorded},
		m.Compare(&recorded, &incoming))

	if len(report) > 4_000 {
		t.Errorf("report is %d bytes, want it truncated", len(report))
	}
	if !strings.Contains(report, "bytes total") {
		t.Errorf("truncated report should say how big the value was:\n%s", report)
	}
}

func TestJSONDiff(t *testing.T) {
	tests := []struct {
		name     string
		recorded string
		incoming string
		want     []string
	}{
		{
			name:     "changed scalar",
			recorded: `{"amount":1}`,
			incoming: `{"amount":2}`,
			want:     []string{"amount: recorded 1, incoming 2"},
		},
		{
			name:     "nested path",
			recorded: `{"card":{"last4":"1111"}}`,
			incoming: `{"card":{"last4":"4242"}}`,
			want:     []string{`card.last4: recorded "1111", incoming "4242"`},
		},
		{
			name:     "only in incoming",
			recorded: `{"a":1}`,
			incoming: `{"a":1,"b":2}`,
			want:     []string{"b: only in incoming (2)"},
		},
		{
			name:     "only in recorded",
			recorded: `{"a":1,"b":2}`,
			incoming: `{"a":1}`,
			want:     []string{"b: only in recorded (2)"},
		},
		{
			name:     "root scalar",
			recorded: `1`,
			incoming: `2`,
			want:     []string{"(root): recorded 1, incoming 2"},
		},
		{
			name:     "not json yields nothing",
			recorded: `plain`,
			incoming: `other`,
			want:     nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := jsonDiff([]byte(tt.recorded), []byte(tt.incoming))
			if len(got) != len(tt.want) {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("got[%d] = %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}

// Diff output feeds an error message a human reads; it must not reorder itself
// between runs.
func TestJSONDiffIsDeterministic(t *testing.T) {
	recorded := []byte(`{"a":1,"b":2,"c":3,"d":4,"e":5,"f":6}`)
	incoming := []byte(`{"a":9,"b":9,"c":9,"d":9,"e":9,"f":9}`)
	first := strings.Join(jsonDiff(recorded, incoming), "|")
	for i := 0; i < 20; i++ {
		if got := strings.Join(jsonDiff(recorded, incoming), "|"); got != first {
			t.Fatalf("run %d differs:\n%s\nvs\n%s", i, first, got)
		}
	}
}

func TestJSONDiffCapsFieldCount(t *testing.T) {
	var rec, in strings.Builder
	rec.WriteString("{")
	in.WriteString("{")
	for i := 0; i < 100; i++ {
		if i > 0 {
			rec.WriteString(",")
			in.WriteString(",")
		}
		key := strings.Repeat("k", 1+i%5) + string(rune('a'+i%26)) + string(rune('0'+i%10))
		rec.WriteString(`"` + key + `":1`)
		in.WriteString(`"` + key + `":2`)
	}
	rec.WriteString("}")
	in.WriteString("}")

	got := jsonDiff([]byte(rec.String()), []byte(in.String()))
	if len(got) > maxDiffFields+1 {
		t.Errorf("got %d entries, want at most %d plus an overflow note",
			len(got), maxDiffFields)
	}
	if !strings.Contains(got[len(got)-1], "more field") {
		t.Errorf("last entry = %q, want an overflow note", got[len(got)-1])
	}
}
