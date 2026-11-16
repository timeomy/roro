package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/spf13/cobra"

	"github.com/timeomy/tollgate/internal/app"
	"github.com/timeomy/tollgate/internal/config"
	"github.com/timeomy/tollgate/internal/gate"
	"github.com/timeomy/tollgate/internal/identity"
	"github.com/timeomy/tollgate/internal/observe"
	"github.com/timeomy/tollgate/internal/proxy"
)

func newServeCmd(root *rootFlags) *cobra.Command {
	var listen string
	cmd := &cobra.Command{
		Use:   "serve [flags] [-- COMMAND [ARGS...]]",
		Short: "Serve MCP over streamable HTTP with policy enforcement",
		Long: `serve listens for MCP streamable HTTP clients at http://LISTEN/mcp and
proxies each session to the upstream (the command after "--", or
upstream.command / upstream.url in the config). Each session gets its own
upstream connection.

Clients authenticate with "Authorization: Bearer <token>". Tokens map to
agents under http.agents (store only token_sha256; create tokens with
"tollgate token new"). Without any http.agents, serve refuses to start.

v0.1 answers with application/json and does not offer the optional GET event
stream, so server-initiated requests (sampling, elicitation) are not relayed
in HTTP mode. Use "wrap" (stdio) if your server needs them.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) > 0 && cmd.ArgsLenAtDash() != 0 {
				return errors.New(`put the upstream server command after "--"`)
			}
			return runServe(cmd.Context(), root, listen, args)
		},
	}
	cmd.Flags().StringVar(&listen, "listen", "", "host:port to listen on (default: http.listen in config)")
	return cmd
}

func runServe(ctx context.Context, root *rootFlags, listen string, command []string) error {
	logger, err := root.newLogger()
	if err != nil {
		return err
	}
	cfg, err := root.loadConfig()
	if err != nil {
		return err
	}
	if listen == "" {
		listen = cfg.HTTP.Listen
	}
	if len(command) == 0 {
		command = cfg.Upstream.Command
	}
	if len(command) == 0 && cfg.Upstream.URL == "" {
		return errors.New(`no upstream: give a command after "--" or set upstream.command / upstream.url`)
	}
	dir, err := tokenDirectory(cfg)
	if err != nil {
		return err
	}
	server, err := app.ServerName(cfg, command)
	if err != nil {
		return err
	}
	rt, err := app.Open(ctx, cfg, logger, version)
	if err != nil {
		return err
	}
	defer rt.Close()

	hs, err := proxy.NewHTTPServer(proxy.HTTPOptions{
		Authenticate:   func(r *http.Request) (identity.Agent, bool) { return dir.Lookup(bearer(r)) },
		NewBackend:     backendFactory(rt, cfg, server, command),
		AllowedOrigins: cfg.HTTP.AllowedOrigins,
		MaxBodyBytes:   cfg.HTTP.MaxBodyBytes,
		IdleTimeout:    cfg.HTTP.SessionIdle.Duration,
		Logger:         logger,
	})
	if err != nil {
		return err
	}
	defer hs.Close()
	return listenAndServe(ctx, cfg, listen, hs, logger)
}

func tokenDirectory(cfg *config.Config) (*identity.Directory, error) {
	if len(cfg.HTTP.Agents) == 0 {
		return nil, errors.New("serve needs at least one entry under http.agents (create a token with `tollgate token new`)")
	}
	entries := make([]identity.TokenEntry, 0, len(cfg.HTTP.Agents))
	for _, a := range cfg.HTTP.Agents {
		entries = append(entries, identity.TokenEntry{
			Agent:  identity.Agent{Name: a.Name, Client: a.Client, Owner: a.Owner},
			Digest: a.TokenSHA256,
		})
	}
	return identity.NewDirectory(entries)
}

func bearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if len(h) > 7 && strings.EqualFold(h[:7], "bearer ") {
		return strings.TrimSpace(h[7:])
	}
	return ""
}

func backendFactory(rt *app.Runtime, cfg *config.Config, server string, command []string) func(context.Context, identity.Agent, string) (*proxy.Backend, error) {
	return func(ctx context.Context, agent identity.Agent, sessionID string) (*proxy.Backend, error) {
		sess, err := gate.NewSession(rt.Deps(), gate.SessionInfo{
			Agent: agent, Server: server, Transport: observe.TransportTCP, SessionID: sessionID,
		})
		if err != nil {
			return nil, err
		}
		if cfg.Upstream.URL != "" && len(command) == 0 {
			conn, err := (&mcp.StreamableClientTransport{Endpoint: cfg.Upstream.URL}).Connect(ctx)
			if err != nil {
				return nil, fmt.Errorf("connect upstream %s: %w", cfg.Upstream.URL, err)
			}
			return &proxy.Backend{Interceptor: sess, Upstream: conn}, nil
		}
		conn, stop, err := proxy.StartCommand(ctx, command[0], command[1:], nil, proxy.DefaultTerminateGrace)
		if err != nil {
			return nil, err
		}
		return &proxy.Backend{Interceptor: sess, Upstream: conn, Stop: stop}, nil
	}
}

func listenAndServe(ctx context.Context, cfg *config.Config, listen string, h http.Handler, log interface {
	Info(string, ...any)
	Warn(string, ...any)
}) error {
	mux := http.NewServeMux()
	mux.Handle("/mcp", h)
	srv := &http.Server{Addr: listen, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return err
	}
	host, _, _ := net.SplitHostPort(listen)
	if ip := net.ParseIP(host); cfg.HTTP.TLS == nil && host != "localhost" && (ip == nil || !ip.IsLoopback()) {
		log.Warn("listening on a non-loopback address without TLS; bearer tokens travel in clear text", "listen", listen)
	}
	errc := make(chan error, 1)
	go func() {
		if cfg.HTTP.TLS != nil {
			errc <- srv.ServeTLS(ln, cfg.HTTP.TLS.CertFile, cfg.HTTP.TLS.KeyFile)
		} else {
			errc <- srv.Serve(ln)
		}
	}()
	log.Info("serving MCP over HTTP", "url", "http://"+ln.Addr().String()+"/mcp")
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
		return nil
	}
}
