// Command hrp is an HTTP record & replay proxy.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/nhan4013/hrp/internal/cassette"
	"github.com/nhan4013/hrp/internal/matcher"
	"github.com/nhan4013/hrp/internal/proxy"
)

func main() {
	listen := flag.String("listen", ":8080", "address to listen on")
	upstream := flag.String("upstream", "", "upstream base URL, e.g. https://sandbox.vendor.com (required unless -mode replay)")
	cassettePath := flag.String("cassette", "", "cassette file to record into or replay from")
	name := flag.String("name", "", "cassette name (default: cassette file base name)")
	mode := flag.String("mode", "", "record | replay (default: record when -cassette is set, otherwise plain forwarding)")
	flag.Parse()

	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, nil)))

	if err := run(*listen, *upstream, *cassettePath, *name, *mode); err != nil {
		slog.Error("hrp failed", "err", err)
		os.Exit(1)
	}
}

func run(listen, upstream, cassettePath, name, modeFlag string) error {
	mode, err := resolveMode(modeFlag, cassettePath)
	if err != nil {
		return err
	}
	if mode != proxy.ModeReplay && upstream == "" {
		return errors.New("-upstream is required unless -mode replay")
	}

	cfg := proxy.Config{Listen: listen, Upstream: upstream, Mode: mode}

	if cassettePath != "" {
		// Replay against a cassette that is not there would answer every request
		// with "nothing recorded", which reads like a matching bug rather than a
		// wrong path. Fail loudly instead.
		if mode == proxy.ModeReplay {
			if _, err := os.Stat(cassettePath); err != nil {
				return fmt.Errorf("cassette to replay: %w", err)
			}
		}
		if name == "" {
			name = strings.TrimSuffix(filepath.Base(cassettePath), filepath.Ext(cassettePath))
		}
		if cfg.Store, err = cassette.Load(cassettePath, name, upstream); err != nil {
			return err
		}
	}

	switch mode {
	case proxy.ModeReplay:
		if cfg.Matcher, err = matcher.New(matcher.DefaultRules); err != nil {
			return err
		}
		slog.Info("replaying", "cassette", cassettePath,
			"interactions", cfg.Store.Len(), "match_on", cfg.Matcher.Rules())
	case proxy.ModeRecord:
		slog.Info("recording", "cassette", cassettePath,
			"existing_interactions", cfg.Store.Len())
	case proxy.ModePassthrough:
	}

	srv, err := proxy.New(cfg)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return srv.Run(ctx)
}

func resolveMode(mode, cassettePath string) (proxy.Mode, error) {
	switch mode {
	case "":
		if cassettePath == "" {
			return proxy.ModePassthrough, nil
		}
		return proxy.ModeRecord, nil
	case string(proxy.ModeRecord), string(proxy.ModeReplay):
		if cassettePath == "" {
			return "", fmt.Errorf("-mode %s requires -cassette", mode)
		}
		return proxy.Mode(mode), nil
	default:
		return "", fmt.Errorf("unknown -mode %q, want %s or %s",
			mode, proxy.ModeRecord, proxy.ModeReplay)
	}
}
