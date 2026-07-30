// Command hrp is an HTTP record & replay proxy.
package main

import (
	"log/slog"
	"os"

	"github.com/nhan4013/hrp/internal/cli"
)

func main() {
	if err := cli.Execute(); err != nil {
		slog.Error("hrp failed", "err", err)
		os.Exit(1)
	}
}
