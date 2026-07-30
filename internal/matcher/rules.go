package matcher

import (
	"bytes"
	"encoding/json"
	"net/url"
	"reflect"
	"sort"
	"strings"

	"github.com/nhan4013/hrp/internal/cassette"
)

// Rule weights. Method, host and path together outweigh everything else, so
// ranking candidates by score surfaces one that addresses the same endpoint.
const (
	weightMethod = 4
	weightHost   = 4
	weightPath   = 4
	weightQuery  = 1
	weightBody   = 1
)

type methodRule struct{}

func (methodRule) Name() string    { return "method" }
func (methodRule) Weight() float64 { return weightMethod }
func (methodRule) Compare(recorded, incoming *cassette.Request) *Mismatch {
	if strings.EqualFold(recorded.Method, incoming.Method) {
		return nil
	}
	return &Mismatch{Rule: "method", Recorded: recorded.Method, Incoming: incoming.Method}
}

type hostRule struct{}

func (hostRule) Name() string    { return "host" }
func (hostRule) Weight() float64 { return weightHost }

// Compare treats an absent scheme or host on either side as a wildcard:
// cassettes recorded through the reverse proxy carry no host at all, and they
// must still match the calls they recorded.
func (hostRule) Compare(recorded, incoming *cassette.Request) *Mismatch {
	if recorded.Host == "" || incoming.Host == "" {
		return nil
	}
	schemeAgree := recorded.Scheme == "" || incoming.Scheme == "" ||
		recorded.Scheme == incoming.Scheme
	if schemeAgree && strings.EqualFold(recorded.Host, incoming.Host) {
		return nil
	}
	return &Mismatch{Rule: "host", Recorded: authority(recorded), Incoming: authority(incoming)}
}

func authority(r *cassette.Request) string {
	if r.Scheme == "" {
		return r.Host
	}
	return r.Scheme + "://" + r.Host
}

type pathRule struct{}

func (pathRule) Name() string    { return "path" }
func (pathRule) Weight() float64 { return weightPath }

// Compare matches paths exactly. Normalizing trailing slashes or case would
// silently accept calls the vendor would treat as different endpoints.
func (pathRule) Compare(recorded, incoming *cassette.Request) *Mismatch {
	if recorded.Path == incoming.Path {
		return nil
	}
	return &Mismatch{Rule: "path", Recorded: recorded.Path, Incoming: incoming.Path}
}

type queryRule struct {
	ignore map[string]struct{}
}

func newQueryRule(ignore []string) queryRule {
	r := queryRule{ignore: make(map[string]struct{}, len(ignore))}
	for _, key := range ignore {
		if key = strings.ToLower(strings.TrimSpace(key)); key != "" {
			r.ignore[key] = struct{}{}
		}
	}
	return r
}

func (queryRule) Name() string    { return "query" }
func (queryRule) Weight() float64 { return weightQuery }

func (r queryRule) Compare(recorded, incoming *cassette.Request) *Mismatch {
	rec, in := r.filter(recorded.Query), r.filter(incoming.Query)
	recEnc, inEnc := rec.Encode(), in.Encode()
	if recEnc == inEnc {
		return nil
	}
	return &Mismatch{
		Rule:     "query",
		Recorded: recEnc,
		Incoming: inEnc,
		Details:  queryDiff(rec, in),
	}
}

func (r queryRule) filter(q map[string][]string) url.Values {
	out := make(url.Values, len(q))
	for key, values := range q {
		if _, skip := r.ignore[strings.ToLower(key)]; skip {
			continue
		}
		out[key] = values
	}
	return out
}

func queryDiff(recorded, incoming url.Values) []string {
	keys := make(map[string]struct{}, len(recorded)+len(incoming))
	for key := range recorded {
		keys[key] = struct{}{}
	}
	for key := range incoming {
		keys[key] = struct{}{}
	}

	var out []string
	for key := range keys {
		rec, in := recorded[key], incoming[key]
		if reflect.DeepEqual(rec, in) {
			continue
		}
		switch {
		case len(rec) == 0:
			out = append(out, key+": only in incoming ("+strings.Join(in, ",")+")")
		case len(in) == 0:
			out = append(out, key+": only in recorded ("+strings.Join(rec, ",")+")")
		default:
			out = append(out, key+": recorded "+strings.Join(rec, ",")+
				", incoming "+strings.Join(in, ","))
		}
	}
	sort.Strings(out)
	return out
}

type bodyRule struct{}

func (bodyRule) Name() string    { return "body" }
func (bodyRule) Weight() float64 { return weightBody }

func (bodyRule) Compare(recorded, incoming *cassette.Request) *Mismatch {
	// Identical bytes: the hashes settle it without decoding anything.
	if recorded.BodyHash != "" && recorded.BodyHash == incoming.BodyHash {
		return nil
	}

	recRaw, recErr := cassette.DecodeBody(recorded.Body, recorded.BodyEncoding)
	inRaw, inErr := cassette.DecodeBody(incoming.Body, incoming.BodyEncoding)
	if recErr != nil || inErr != nil {
		// An undecodable stored body is a corrupt cassette, not a match.
		if recorded.Body == incoming.Body {
			return nil
		}
		return &Mismatch{Rule: "body", Recorded: recorded.Body, Incoming: incoming.Body}
	}

	if bodiesEqual(recRaw, inRaw) {
		return nil
	}
	return &Mismatch{
		Rule:     "body",
		Recorded: string(recRaw),
		Incoming: string(inRaw),
		Details:  jsonDiff(recRaw, inRaw),
	}
}

// bodiesEqual compares two bodies, ignoring JSON key order: a client whose map
// serializes in a different order is still making the same call. Anything that
// is not JSON is compared byte for byte.
func bodiesEqual(recorded, incoming []byte) bool {
	if bytes.Equal(recorded, incoming) {
		return true
	}
	var rec, in any
	if json.Unmarshal(recorded, &rec) != nil || json.Unmarshal(incoming, &in) != nil {
		return false
	}
	return reflect.DeepEqual(rec, in)
}
