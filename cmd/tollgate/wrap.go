package main

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/timeomy/tollgate/internal/app"
	"github.com/timeomy/tollgate/internal/audit"
	"github.com/timeomy/tollgate/internal/config"
	"github.com/timeomy/tollgate/internal/gate"
	"github.com/timeomy/tollgate/internal/identity"
	"github.com/timeomy/tollgate/internal/observe"
	"github.com/timeomy/tollgate/internal/proxy"
)

type agentFlags struct {
	name, client, owner string
}

func (a *agentFlags) register(cmd *cobra.Command) {
	cmd.Flags().StringVar(&a.name, "agent", "", "agent name (default: $TOLLGATE_AGENT, else agent.name in config)")
	cmd.Flags().StringVar(&a.client, "client", "", "agent client, e.g. cursor (default: agent.client in config)")
	cmd.Flags().StringVar(&a.owner, "owner", "", "accountable owner (default: agent.owner in config)")
}

// resolve picks the agent identity: flag, then environment, then config.
func (a *agentFlags) resolve(cfg *config.Config) (identity.Agent, error) {
	ag := identity.Agent{Name: cfg.Agent.Name, Client: cfg.Agent.Client, Owner: cfg.Agent.Owner}
	if env := os.Getenv("TOLLGATE_AGENT"); env != "" {
		ag.Name = env
	}
	if a.name != "" {
		ag.Name = a.name
	}
	if a.client != "" {
		ag.Client = a.client
	}
	if a.owner != "" {
		ag.Owner = a.owner
	}
	return ag, ag.Validate()
}

func newWrapCmd(root *rootFlags) *cobra.Command {
	var af agentFlags
	cmd := &cobra.Command{
		Use:   "wrap [flags] -- COMMAND [ARGS...]",
		Short: "Proxy a local stdio MCP server with policy enforcement",
		Long: `wrap starts COMMAND as the upstream MCP server and relays MCP traffic
between it and the client on Tollgate's own stdin/stdout. Every tools/call
is checked (kill switch, tool pinning, Cedar policy, approval) and audited.

Use it as a drop-in replacement for the server command in an MCP client
config: "command" becomes the tollgate binary and "args" become
["--config", "/abs/tollgate.yaml", "wrap", "--agent", "cursor", "--", <original command and args>].

Tollgate refuses to start (fail closed) if the config, policy, signing key,
or agent identity is missing or invalid.`,
		Example: `  tollgate --config ~/tollgate/tollgate.yaml wrap --agent cursor -- npx -y @modelcontextprotocol/server-filesystem /tmp/sandbox
  tollgate wrap --agent research-bot --log-level debug -- ./my-mcp-server`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) > 0 && cmd.ArgsLenAtDash() != 0 {
				return errors.New(`put the upstream server command after "--", for example: tollgate wrap -- my-mcp-server`)
			}
			return runWrap(cmd.Context(), root, &af, args)
		},
	}
	af.register(cmd)
	return cmd
}

func runWrap(ctx context.Context, root *rootFlags, af *agentFlags, command []string) error {
	logger, err := root.newLogger()
	if err != nil {
		return err
	}
	cfg, err := root.loadConfig()
	if err != nil {
		return err
	}
	if len(command) == 0 {
		command = cfg.Upstream.Command
	}
	if len(command) == 0 {
		return errors.New(`no upstream command: give it after "--" or set upstream.command`)
	}
	agent, err := af.resolve(cfg)
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

	sessionID := rand.Text()[:16]
	sess, err := gate.NewSession(rt.Deps(), gate.SessionInfo{
		Agent: agent, Server: server, Transport: observe.TransportPipe, SessionID: sessionID,
	})
	if err != nil {
		return err
	}
	logSession(ctx, rt, agent, server, sessionID, "session_start")
	defer logSession(context.Background(), rt, agent, server, sessionID, "session_end")

	logger.Info("proxying stdio MCP server", "agent", agent.Name, "server", server, "upstream", command[0])
	return proxy.RunStdio(ctx, proxy.StdioOptions{
		Command: command[0], Args: command[1:], Interceptor: sess, Logger: logger,
	})
}

func logSession(ctx context.Context, rt *app.Runtime, agent identity.Agent, server, id, reason string) {
	_, err := rt.Audit.Append(context.WithoutCancel(ctx), audit.Event{
		Kind: audit.KindSession, Agent: agent.Name, Server: server, Session: id, Reason: reason,
		Detail: fmt.Sprintf("client=%s owner=%s", agent.Client, agent.Owner),
	})
	if err != nil {
		rt.Logger.Error("audit append failed", "err", err)
	}
}
