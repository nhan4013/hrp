// Package cli wires the hrp commands together.
package cli

import (
	"log/slog"
	"os"

	"github.com/spf13/cobra"
)

// Execute runs the hrp command line. It returns an error rather than exiting, so
// main owns the process exit code.
func Execute() error {
	root := &cobra.Command{
		Use:   "hrp",
		Short: "HTTP record & replay proxy",
		Long: "hrp sits between your app and a third-party API. It records real\n" +
			"traffic into a plain-YAML cassette, then replays it so tests run\n" +
			"without touching the network.",
		SilenceUsage:  true,
		SilenceErrors: true,
		// Cobra prints usage for a bad invocation; a failure inside a command is
		// already reported by main and does not need the whole help text again.
		PersistentPreRun: func(cmd *cobra.Command, _ []string) {
			slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, nil)))
		},
	}

	root.AddCommand(
		recordCmd(),
		replayCmd(),
		autoCmd(),
		proxyCmd(),
		inspectCmd(),
		scanCmd(),
	)
	return root.Execute()
}
