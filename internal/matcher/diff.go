package matcher

import (
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"

	"github.com/nhan4013/hrp/internal/cassette"
)

const (
	// maxDiffValue caps how much of a value the report prints. A 10 MiB body
	// dumped into an error response is not a diagnostic, it is a wall.
	maxDiffValue = 300
	// maxDiffFields caps how many individual field differences are listed.
	maxDiffFields = 20
)

// Explain renders a report saying why an incoming request matched nothing.
// best may be nil when the cassette holds no interactions at all.
func Explain(incoming *cassette.Request, best *cassette.Interaction, res Result) string {
	var b strings.Builder

	fmt.Fprintf(&b, "No recorded interaction matches %s %s\n", incoming.Method, incoming.Path)

	if best == nil {
		b.WriteString("\n  The cassette holds no interactions to match against.\n" +
			"  Record this traffic first, then replay it.\n")
		return b.String()
	}

	fmt.Fprintf(&b, "\n  Closest candidate: %s (%s %s), score %.2f\n",
		best.ID, best.Request.Method, best.Request.Path, res.Score)

	names := make([]string, 0, len(res.Mismatches))
	for _, m := range res.Mismatches {
		names = append(names, m.Rule)
	}
	fmt.Fprintf(&b, "  Differs on: %s\n", strings.Join(names, ", "))

	for _, m := range res.Mismatches {
		fmt.Fprintf(&b, "\n  [%s]\n    - recorded: %s\n    + incoming: %s\n",
			m.Rule, truncate(m.Recorded), truncate(m.Incoming))
		for _, detail := range m.Details {
			fmt.Fprintf(&b, "      %s\n", detail)
		}
	}
	return b.String()
}

// jsonDiff lists the field paths at which two JSON documents differ. It returns
// nil for anything that is not JSON, leaving the caller to show whole values.
//
// ponytail: arrays are compared as a single leaf value. Per-element array diffs
// would need a sequence alignment; add one if array-heavy APIs make this noisy.
func jsonDiff(recorded, incoming []byte) []string {
	var rec, in any
	if json.Unmarshal(recorded, &rec) != nil || json.Unmarshal(incoming, &in) != nil {
		return nil
	}
	var out []string
	walkDiff("", rec, in, &out)
	sort.Strings(out)
	if len(out) > maxDiffFields {
		extra := len(out) - maxDiffFields
		out = append(out[:maxDiffFields:maxDiffFields],
			fmt.Sprintf("... and %d more field(s)", extra))
	}
	return out
}

func walkDiff(path string, recorded, incoming any, out *[]string) {
	recMap, recIsMap := recorded.(map[string]any)
	inMap, inIsMap := incoming.(map[string]any)
	if recIsMap && inIsMap {
		keys := make(map[string]struct{}, len(recMap)+len(inMap))
		for key := range recMap {
			keys[key] = struct{}{}
		}
		for key := range inMap {
			keys[key] = struct{}{}
		}
		for key := range keys {
			recVal, inRec := recMap[key]
			inVal, inInc := inMap[key]
			child := key
			if path != "" {
				child = path + "." + key
			}
			switch {
			case !inRec:
				*out = append(*out, fmt.Sprintf("%s: only in incoming (%s)", child, format(inVal)))
			case !inInc:
				*out = append(*out, fmt.Sprintf("%s: only in recorded (%s)", child, format(recVal)))
			default:
				walkDiff(child, recVal, inVal, out)
			}
		}
		return
	}

	if reflect.DeepEqual(recorded, incoming) {
		return
	}
	label := path
	if label == "" {
		label = "(root)"
	}
	*out = append(*out, fmt.Sprintf("%s: recorded %s, incoming %s",
		label, format(recorded), format(incoming)))
}

// format renders a decoded JSON value the way it appeared in the document,
// so a string shows its quotes and a number does not gain a ".000000".
func format(v any) string {
	out, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprintf("%v", v)
	}
	return truncate(string(out))
}

func truncate(s string) string {
	if len(s) <= maxDiffValue {
		return s
	}
	return s[:maxDiffValue] + fmt.Sprintf("... (%d bytes total)", len(s))
}
