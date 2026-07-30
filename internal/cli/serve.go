package cli

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/nhan4013/hrp/internal/cassette"
	"github.com/nhan4013/hrp/internal/matcher"
	"github.com/nhan4013/hrp/internal/proxy"
)

// serveFlags are shared by every command that starts a proxy. The four commands
// differ only in mode and in which flags they require, so they share one builder
// rather than one file each.
type serveFlags struct {
	listen       string
	upstream     string
	cassettePath string
	name         string
	ignoreQuery  []string
}

func serveCommand(mode proxy.Mode, use, short, long, example string) *cobra.Command {
	var f serveFlags

	cmd := &cobra.Command{
		Use:     use,
		Short:   short,
		Long:    long,
		Example: example,
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return serve(cmd.Context(), mode, f)
		},
	}

	cmd.Flags().StringVarP(&f.listen, "listen", "l", ":8080", "address to listen on")
	if mode != proxy.ModeReplay {
		cmd.Flags().StringVarP(&f.upstream, "upstream", "u", "",
			"upstream base URL, e.g. https://sandbox.vendor.com")
		// MarkFlagRequired only fails for a flag that was never defined.
		_ = cmd.MarkFlagRequired("upstream")
	}
	if mode != proxy.ModePassthrough {
		cmd.Flags().StringVarP(&f.cassettePath, "cassette", "c", "", "cassette file")
		_ = cmd.MarkFlagRequired("cassette")
		cmd.Flags().StringVar(&f.name, "name", "",
			"cassette name (default: cassette file base name)")
	}
	if mode == proxy.ModeReplay || mode == proxy.ModeAuto {
		cmd.Flags().StringSliceVar(&f.ignoreQuery, "ignore-query", nil,
			"query parameters to exclude from matching, e.g. timestamp,nonce")
	}
	return cmd
}

func recordCmd() *cobra.Command {
	return serveCommand(proxy.ModeRecord, "record", "Forward upstream and record every interaction",
		"Forward every request to the upstream and record the request/response\n"+
			"pair into the cassette. Interactions already present are left alone,\n"+
			"so recording twice does not grow the file.",
		"  hrp record -u https://sandbox.vendor.com -c ./cassettes/payment.yaml")
}

func replayCmd() *cobra.Command {
	return serveCommand(proxy.ModeReplay, "replay", "Serve from the cassette, never touch the network",
		"Answer every request from the cassette. Nothing leaves the machine, so\n"+
			"no upstream is needed. A request that matches nothing returns 599 with\n"+
			"a report naming the closest recorded interaction and how it differs.",
		"  hrp replay -c ./cassettes/payment.yaml")
}

func autoCmd() *cobra.Command {
	return serveCommand(proxy.ModeAuto, "auto", "Replay what is recorded, record what is not",
		"Serve from the cassette when a request matches, otherwise forward it\n"+
			"upstream and record the result. The cassette fills in as you work,\n"+
			"which makes this the mode to leave running during development.",
		"  hrp auto -u https://sandbox.vendor.com -c ./cassettes/payment.yaml")
}

func proxyCmd() *cobra.Command {
	return serveCommand(proxy.ModePassthrough, "proxy", "Forward upstream without recording",
		"Forward every request to the upstream and record nothing. Useful for\n"+
			"watching traffic through the structured request log.",
		"  hrp proxy -u https://sandbox.vendor.com")
}

func serve(ctx context.Context, mode proxy.Mode, f serveFlags) error {
	cfg := proxy.Config{Listen: f.listen, Upstream: f.upstream, Mode: mode}

	if f.cassettePath != "" {
		// Replaying against a cassette that is not there would answer every
		// request with "nothing recorded", which reads like a matching bug rather
		// than a wrong path. Fail loudly instead.
		if mode == proxy.ModeReplay {
			if _, err := os.Stat(f.cassettePath); err != nil {
				return fmt.Errorf("cassette to replay: %w", err)
			}
		}
		name := f.name
		if name == "" {
			name = strings.TrimSuffix(filepath.Base(f.cassettePath),
				filepath.Ext(f.cassettePath))
		}
		store, err := cassette.Load(f.cassettePath, name, f.upstream)
		if err != nil {
			return err
		}
		cfg.Store = store
	}

	if mode == proxy.ModeReplay || mode == proxy.ModeAuto {
		var opts []matcher.Option
		if len(f.ignoreQuery) > 0 {
			opts = append(opts, matcher.IgnoreQuery(f.ignoreQuery...))
		}
		m, err := matcher.New(matcher.DefaultRules, opts...)
		if err != nil {
			return err
		}
		cfg.Matcher = m
		slog.Info("matching", "on", m.Rules(), "ignore_query", f.ignoreQuery)
	}
	if cfg.Store != nil {
		slog.Info("cassette", "path", f.cassettePath, "interactions", cfg.Store.Len())
	}

	srv, err := proxy.New(cfg)
	if err != nil {
		return err
	}

	if ctx == nil {
		ctx = context.Background()
	}
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	return srv.Run(ctx)
}
