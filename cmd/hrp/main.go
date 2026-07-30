// Command hrp is an HTTP record & replay proxy.
package main

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/nhan4013/hrp/internal/cassette"
	"github.com/nhan4013/hrp/internal/proxy"
)

func main() {
	listen := flag.String("listen", ":8080", "address to listen on")
	upstream := flag.String("upstream", "", "upstream base URL, e.g. https://sandbox.vendor.com (required)")
	cassettePath := flag.String("cassette", "", "record interactions to this cassette file (default: no recording)")
	name := flag.String("name", "", "cassette name (default: cassette file base name)")
	flag.Parse()

	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, nil)))

	if err := run(*listen, *upstream, *cassettePath, *name); err != nil {
		slog.Error("hrp failed", "err", err)
		os.Exit(1)
	}
}

func run(listen, upstream, cassettePath, name string) error {
	if upstream == "" {
		return errors.New("-upstream is required")
	}

	var store *cassette.Store
	if cassettePath != "" {
		if name == "" {
			name = strings.TrimSuffix(filepath.Base(cassettePath),
				filepath.Ext(cassettePath))
		}
		var err error
		if store, err = cassette.Load(cassettePath, name, upstream); err != nil {
			return err
		}
		slog.Info("recording", "cassette", cassettePath, "existing_interactions", store.Len())
	}

	srv, err := proxy.New(listen, upstream, store)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return srv.Run(ctx)
}
