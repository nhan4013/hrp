// Command hrp is an HTTP record & replay proxy.
package main

import (
	"log/slog"
	"os"

	"github.com/nhan4013/hrp/internal/cli"
)

func main() {
	err := cli.Execute()
	if err == nil {
		return
	}
	// hrp scan signals "secrets found" with an empty error: the report is already
	// on stdout and a second line under it would only be noise.
	if err.Error() != "" {
		slog.Error("hrp failed", "err", err)
	}
	os.Exit(1)
}
