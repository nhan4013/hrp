package cli

import (
	"errors"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/nhan4013/hrp/internal/cassette"
	"github.com/nhan4013/hrp/internal/config"
	"github.com/nhan4013/hrp/internal/scan"
)

// errSecretsFound makes the command exit non-zero without printing a second
// error line under the report. main turns any error into exit status 1, which is
// what a pre-commit hook or a CI step checks.
var errSecretsFound = errors.New("")

func scanCmd() *cobra.Command {
	var configPath string

	cmd := &cobra.Command{
		Use:   "scan <cassette>...",
		Short: "Look for secrets a cassette should not be carrying",
		Long: "Scan cassettes for values that look like secrets and exit non-zero if\n" +
			"any are found, so this can run in a pre-commit hook or a CI step.\n\n" +
			"Detectors are built in and need no configuration: a cassette is about\n" +
			"to be committed, so the last line of defence has to work out of the\n" +
			"box. Passing --config adds that file's redact.patterns as extra\n" +
			"detectors, so anything worth hiding is also reported when it slips\n" +
			"through.\n\n" +
			"Shapes that cannot be told from ordinary data — a 12-digit national\n" +
			"ID, a phone number — are not built in, because a scanner that cries\n" +
			"wolf gets switched off. Add those as config patterns.",
		Example: "  hrp scan ./cassettes/*.yaml\n" +
			"  hrp scan --config hrp.yaml ./cassettes/payment.yaml",
		Args:         cobra.MinimumNArgs(1),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			var conf *config.Config
			if configPath != "" {
				var err error
				if conf, err = config.Load(configPath); err != nil {
					return err
				}
			}
			scanner, err := buildScanner(conf)
			if err != nil {
				return err
			}
			return runScan(cmd.OutOrStdout(), scanner, args)
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "",
		"hrp.yaml whose redact.patterns are added as detectors")
	return cmd
}

func runScan(out io.Writer, scanner *scan.Scanner, paths []string) error {
	var buf strings.Builder
	total := 0

	for _, path := range paths {
		store, err := cassette.Load(path, "", "")
		if err != nil {
			return err
		}
		findings := scanner.Interactions(store.Interactions())
		if len(findings) == 0 {
			_, _ = fmt.Fprintf(&buf, "ok    %s\n", path)
			continue
		}

		total += len(findings)
		_, _ = fmt.Fprintf(&buf, "FOUND %s — %d suspected secret(s)\n\n", path, len(findings))
		tw := tabwriter.NewWriter(&buf, 0, 0, 2, ' ', 0)
		_, _ = fmt.Fprintln(tw, "  INTERACTION\tLOCATION\tDETECTOR\tEXCERPT")
		for _, f := range findings {
			_, _ = fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\n",
				f.Interaction, f.Location, f.Detector, f.Excerpt)
		}
		if err := tw.Flush(); err != nil {
			return fmt.Errorf("render findings: %w", err)
		}
		buf.WriteString("\n")
	}

	if total > 0 {
		_, _ = fmt.Fprintf(&buf,
			"%d suspected secret(s). Redact them before committing: add the header,\n"+
				"json_fields or patterns rule to hrp.yaml and re-record.\n", total)
	}

	if _, err := io.WriteString(out, buf.String()); err != nil {
		return err
	}
	if total > 0 {
		return errSecretsFound
	}
	return nil
}
