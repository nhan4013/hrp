package cli

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/nhan4013/hrp/internal/cassette"
	"github.com/nhan4013/hrp/internal/config"
	"github.com/nhan4013/hrp/internal/mitm"
	"github.com/nhan4013/hrp/internal/proxy"
)

// caFlags locates the development CA. Empty means the default under ~/.hrp.
type caFlags struct {
	cert string
	key  string
}

func (f *caFlags) register(cmd *cobra.Command) {
	cmd.Flags().StringVar(&f.cert, "ca-cert", "", "CA certificate path (default ~/.hrp/ca.pem)")
	cmd.Flags().StringVar(&f.key, "ca-key", "", "CA private key path (default ~/.hrp/ca-key.pem)")
}

func (f *caFlags) resolve() (cert, key string, err error) {
	cert, key = f.cert, f.key
	if cert != "" && key != "" {
		return cert, key, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", "", fmt.Errorf("locate home directory for the default CA paths: %w "+
			"(pass --ca-cert and --ca-key explicitly)", err)
	}
	if cert == "" {
		cert = filepath.Join(home, ".hrp", "ca.pem")
	}
	if key == "" {
		key = filepath.Join(home, ".hrp", "ca-key.pem")
	}
	return cert, key, nil
}

func mitmCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "mitm",
		Short: "Forward proxy that terminates TLS, so HTTPS_PROXY is all you need",
		Long: "Run hrp as a forward proxy with a man-in-the-middle CA. The app\n" +
			"keeps its real base URL; only HTTP_PROXY/HTTPS_PROXY point here.\n\n" +
			"CONNECT tunnels are terminated with per-host certificates signed by a\n" +
			"local development CA (see `hrp ca install`). The mode is a subcommand,\n" +
			"as with the reverse proxy: record, replay, auto or proxy.",
	}
	cmd.AddCommand(
		mitmServeCmd(proxy.ModeRecord, "record", "Record HTTPS traffic through the proxy"),
		mitmServeCmd(proxy.ModeReplay, "replay", "Serve HTTPS traffic from the cassette"),
		mitmServeCmd(proxy.ModeAuto, "auto", "Replay what is recorded, record what is not"),
		mitmServeCmd(proxy.ModePassthrough, "proxy", "Forward HTTPS traffic without recording"),
	)
	return cmd
}

func mitmServeCmd(mode proxy.Mode, use, short string) *cobra.Command {
	var f serveFlags
	var ca caFlags

	cmd := &cobra.Command{
		Use:   use,
		Short: short,
		Example: "  HTTPS_PROXY=localhost:8080 ./myapp    # app unchanged\n" +
			"  hrp mitm " + use + " -c ./cassettes/payment.yaml",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return serveMITM(cmd, mode, f, ca)
		},
	}

	cmd.Flags().StringVarP(&f.listen, "listen", "l", ":8080", "address to listen on")
	cmd.Flags().StringVar(&f.configPath, "config", "", "hrp.yaml to read settings from")
	if mode != proxy.ModePassthrough {
		cmd.Flags().StringVarP(&f.cassettePath, "cassette", "c", "", "cassette file")
		cmd.Flags().StringVar(&f.name, "name", "",
			"cassette name (default: cassette file base name)")
	}
	if mode == proxy.ModeReplay || mode == proxy.ModeAuto {
		cmd.Flags().StringSliceVar(&f.ignoreQuery, "ignore-query", nil,
			"query parameters to exclude from matching, e.g. timestamp,nonce")
	}
	ca.register(cmd)
	return cmd
}

func serveMITM(cmd *cobra.Command, mode proxy.Mode, f serveFlags, ca caFlags) error {
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
	cassettePath := f.cassettePath
	if cassettePath == "" && conf != nil {
		cassettePath = conf.Cassette
	}
	if mode != proxy.ModePassthrough && cassettePath == "" {
		return fmt.Errorf("mitm %s needs a cassette: pass --cassette or set it in a --config file", mode)
	}

	certPath, keyPath, err := ca.resolve()
	if err != nil {
		return err
	}
	authority, generated, err := mitm.EnsureCA(certPath, keyPath)
	if err != nil {
		return err
	}
	if generated {
		slog.Info("generated a new development CA", "cert", certPath)
		slog.Info("clients must trust it before HTTPS works", "hint", "hrp ca install")
	}

	cfg := proxy.Config{Listen: listen, Mode: mode, CA: authority}

	if cfg.Redactor, err = buildRedactor(conf); err != nil {
		return err
	}
	if cfg.Fault, err = buildFault(conf); err != nil {
		return err
	}
	if cfg.Fault != nil && cfg.Fault.Active() {
		slog.Warn("fault injection is on", "latency", conf.Fault.Latency,
			"error_rate", conf.Fault.ErrorRate, "hang_rate", conf.Fault.HangRate)
	}

	if cassettePath != "" {
		// Same rule as the reverse proxy: replaying a path that does not exist
		// would answer every request with "nothing recorded".
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
		// No cassette-level upstream: a forward proxy records many of them, so
		// each interaction carries its own scheme and host instead.
		if cfg.Store, err = cassette.Load(cassettePath, name, ""); err != nil {
			return err
		}
		slog.Info("cassette", "path", cassettePath, "interactions", cfg.Store.Len())
	}

	if mode == proxy.ModeReplay || mode == proxy.ModeAuto {
		if cfg.Matcher, err = buildMITMMatcher(conf, f.ignoreQuery); err != nil {
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

func caCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ca",
		Short: "Manage the MITM certificate authority",
	}
	cmd.AddCommand(caInstallCmd())
	return cmd
}

func caInstallCmd() *cobra.Command {
	var ca caFlags

	cmd := &cobra.Command{
		Use:   "install",
		Short: "Create the CA if needed, then show how to make clients trust it",
		Long: "Create the local development CA used by `hrp mitm` when it does not\n" +
			"exist yet, and print the per-tool and system-wide ways to trust it.\n\n" +
			"Trusting per tool (an environment variable) is usually better than a\n" +
			"system-wide install: it works in CI, needs no admin rights, and stops\n" +
			"the moment the variable is unset.",
		Example: "  hrp ca install\n" +
			"  export REQUESTS_CA_BUNDLE=~/.hrp/ca.pem   # Python requests",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			certPath, keyPath, err := ca.resolve()
			if err != nil {
				return err
			}
			authority, generated, err := mitm.EnsureCA(certPath, keyPath)
			if err != nil {
				return err
			}
			return writeCAInstall(cmd.OutOrStdout(), authority, certPath, keyPath, generated)
		},
	}
	ca.register(cmd)
	return cmd
}

func writeCAInstall(out io.Writer, _ *mitm.CA, certPath, keyPath string, generated bool) error {
	var buf strings.Builder

	if generated {
		_, _ = fmt.Fprintf(&buf, "Generated a new development CA:\n  %s\n\n", certPath)
	} else {
		_, _ = fmt.Fprintf(&buf, "CA already exists:\n  %s\n\n", certPath)
	}

	buf.WriteString("Trust it per tool — no admin rights, easy to undo:\n")
	tw := tabwriter.NewWriter(&buf, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintf(tw, "  curl\t--cacert %s  (or export CURL_CA_BUNDLE=%s)\n", certPath, certPath)
	_, _ = fmt.Fprintf(tw, "  Python requests\texport REQUESTS_CA_BUNDLE=%s\n", certPath)
	_, _ = fmt.Fprintf(tw, "  Node\texport NODE_EXTRA_CA_CERTS=%s\n", certPath)
	_, _ = fmt.Fprintf(tw, "  Go\texport SSL_CERT_FILE=%s\n", certPath)
	if err := tw.Flush(); err != nil {
		return fmt.Errorf("render instructions: %w", err)
	}

	_, _ = fmt.Fprintf(&buf, "\nOr trust it system-wide (needs admin rights):\n"+
		"  macOS  sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain %s\n"+
		"  Linux  sudo cp %s /usr/local/share/ca-certificates/hrp-ca.crt && sudo update-ca-certificates\n",
		certPath, certPath)

	_, _ = fmt.Fprintf(&buf, "\n%s signs for any host. Keep it private, keep it out of git,\n"+
		"and remove the trust when you are done.\n", keyPath)

	_, err := io.WriteString(out, buf.String())
	return err
}
