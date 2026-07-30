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
	"github.com/nhan4013/hrp/internal/config"
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
	configPath   string
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
			return serve(cmd, mode, f)
		},
	}

	cmd.Flags().StringVarP(&f.listen, "listen", "l", ":8080", "address to listen on")
	cmd.Flags().StringVar(&f.configPath, "config", "", "hrp.yaml to read settings from")
	if mode != proxy.ModeReplay {
		cmd.Flags().StringVarP(&f.upstream, "upstream", "u", "",
			"upstream base URL, e.g. https://sandbox.vendor.com")
	}
	if mode != proxy.ModePassthrough {
		cmd.Flags().StringVarP(&f.cassettePath, "cassette", "c", "", "cassette file")
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

func serve(cmd *cobra.Command, mode proxy.Mode, f serveFlags) error {
	var conf *config.Config
	if f.configPath != "" {
		var err error
		if conf, err = config.Load(f.configPath); err != nil {
			return err
		}
	}

	// An explicit flag beats the config file; the config file beats the default.
	listen := f.listen
	if conf != nil && conf.Listen != "" && !cmd.Flags().Changed("listen") {
		listen = conf.Listen
	}
	upstream := f.upstream
	if upstream == "" && conf != nil {
		upstream = conf.Upstream
	}
	cassettePath := f.cassettePath
	if cassettePath == "" && conf != nil {
		cassettePath = conf.Cassette
	}

	if mode != proxy.ModeReplay && upstream == "" {
		return fmt.Errorf("%s needs an upstream: pass --upstream or set it in a --config file", mode)
	}
	if mode != proxy.ModePassthrough && cassettePath == "" {
		return fmt.Errorf("%s needs a cassette: pass --cassette or set it in a --config file", mode)
	}

	cfg := proxy.Config{Listen: listen, Upstream: upstream, Mode: mode}

	redactor, err := buildRedactor(conf)
	if err != nil {
		return err
	}
	cfg.Redactor = redactor

	if cfg.Fault, err = buildFault(conf); err != nil {
		return err
	}
	if cfg.Fault != nil && cfg.Fault.Active() {
		slog.Warn("fault injection is on", "latency", conf.Fault.Latency,
			"error_rate", conf.Fault.ErrorRate, "hang_rate", conf.Fault.HangRate)
	}

	if cassettePath != "" {
		// Replaying against a cassette that is not there would answer every
		// request with "nothing recorded", which reads like a matching bug rather
		// than a wrong path. Fail loudly instead.
		if mode == proxy.ModeReplay {
			if _, err := os.Stat(cassettePath); err != nil {
				return fmt.Errorf("cassette to replay: %w", err)
			}
		}
		name := f.name
		if name == "" {
			name = strings.TrimSuffix(filepath.Base(cassettePath),
				filepath.Ext(cassettePath))
		}
		if cfg.Store, err = cassette.Load(cassettePath, name, upstream); err != nil {
			return err
		}
		slog.Info("cassette", "path", cassettePath, "interactions", cfg.Store.Len())
	}

	if mode == proxy.ModeReplay || mode == proxy.ModeAuto {
		if cfg.Matcher, err = buildMatcher(conf, f.ignoreQuery); err != nil {
			return err
		}
		slog.Info("matching", "on", cfg.Matcher.Rules())
	}

	srv, err := proxy.New(cfg)
	if err != nil {
		return err
	}
	return runWithSignals(cmd, srv)
}

// runWithSignals serves until SIGINT or SIGTERM, then lets the server's own
// graceful shutdown (and cassette flush) run.
func runWithSignals(cmd *cobra.Command, srv *proxy.Server) error {
	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	return srv.Run(ctx)
}
