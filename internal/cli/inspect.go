package cli

import (
	"fmt"
	"io"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/nhan4013/hrp/internal/cassette"
)

func inspectCmd() *cobra.Command {
	var sortBy string

	cmd := &cobra.Command{
		Use:   "inspect <cassette>",
		Short: "List the interactions in a cassette",
		Long: "Print a cassette's interactions as a table. The cassette itself is\n" +
			"plain YAML and readable as-is; this is for scanning a large one and\n" +
			"for finding the ID of an interaction that a replay miss mentioned.",
		Example: "  hrp inspect ./cassettes/payment.yaml\n" +
			"  hrp inspect ./cassettes/payment.yaml --sort path",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := cassette.Load(args[0], "", "")
			if err != nil {
				return err
			}
			return writeInspectTable(cmd.OutOrStdout(), args[0], store, sortBy)
		},
	}
	cmd.Flags().StringVar(&sortBy, "sort", "recorded",
		"sort order: recorded, path, or status")
	return cmd
}

func writeInspectTable(out io.Writer, path string, store *cassette.Store, sortBy string) error {
	interactions := store.Interactions()

	if err := sortInteractions(interactions, sortBy); err != nil {
		return err
	}

	// Render into a Builder first, whose Write never fails, then make one
	// checked write to out. That keeps a broken pipe — inspect | head — an error
	// the caller sees, without an error check on every column.
	var buf strings.Builder
	_, _ = fmt.Fprintf(&buf, "%s\n%d interaction(s)\n\n", path, len(interactions))

	if len(interactions) == 0 {
		buf.WriteString("The cassette is empty. Record some traffic first.\n")
		_, err := io.WriteString(out, buf.String())
		return err
	}

	// A forward-proxy cassette spans upstreams, so the host is part of each
	// interaction's identity. A reverse-proxy cassette has one upstream for the
	// whole file; repeating it on every row would be noise, hence no column.
	showHost := false
	for _, in := range interactions {
		if in.Request.Host != "" {
			showHost = true
			break
		}
	}

	tw := tabwriter.NewWriter(&buf, 0, 0, 2, ' ', 0)
	if showHost {
		_, _ = fmt.Fprintln(tw, "ID\tHOST\tMETHOD\tPATH\tQUERY\tSTATUS\tREQ\tRESP\tMS\tHITS")
	} else {
		_, _ = fmt.Fprintln(tw, "ID\tMETHOD\tPATH\tQUERY\tSTATUS\tREQ\tRESP\tMS\tHITS")
	}
	for _, in := range interactions {
		cols := []string{
			in.ID,
			in.Request.Method,
			in.Request.Path,
			dash(url.Values(in.Request.Query).Encode()),
			strconv.Itoa(in.Response.Status),
			bodySize(in.Request.Body, in.Request.BodyEncoding),
			bodySize(in.Response.Body, in.Response.BodyEncoding),
			strconv.FormatInt(in.Response.DurationMS, 10),
			strconv.Itoa(in.Meta.HitCount),
		}
		if showHost {
			host := dash(in.Request.Host)
			if in.Request.Scheme != "" && in.Request.Host != "" {
				host = in.Request.Scheme + "://" + in.Request.Host
			}
			cols = append(cols[:1], append([]string{host}, cols[1:]...)...)
		}
		_, _ = fmt.Fprintln(tw, strings.Join(cols, "\t"))
	}
	if err := tw.Flush(); err != nil {
		return fmt.Errorf("render table: %w", err)
	}

	_, err := io.WriteString(out, buf.String())
	return err
}

func sortInteractions(interactions []cassette.Interaction, sortBy string) error {
	switch sortBy {
	case "recorded":
		// Already in recording order.
	case "path":
		sort.SliceStable(interactions, func(i, j int) bool {
			a, b := interactions[i].Request, interactions[j].Request
			if a.Path != b.Path {
				return a.Path < b.Path
			}
			return a.Method < b.Method
		})
	case "status":
		sort.SliceStable(interactions, func(i, j int) bool {
			return interactions[i].Response.Status < interactions[j].Response.Status
		})
	default:
		return fmt.Errorf("unknown --sort %q, want recorded, path or status", sortBy)
	}
	return nil
}

// bodySize reports the size of the original body, not of its stored form: base64
// inflates by a third and would make a recorded payload look bigger than it is.
func bodySize(body, encoding string) string {
	if body == "" {
		return "-"
	}
	raw, err := cassette.DecodeBody(body, encoding)
	if err != nil {
		return "?"
	}
	return strconv.Itoa(len(raw)) + "B"
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
