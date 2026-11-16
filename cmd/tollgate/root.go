package main

import (
	"fmt"
	"log/slog"
	"os"
	"os/user"
	"strings"

	"github.com/spf13/cobra"

	"github.com/timeomy/tollgate/internal/config"
)

type rootFlags struct {
	logLevel   string
	configPath string
}

func newRootCmd() *cobra.Command {
	flags := &rootFlags{}
	cmd := &cobra.Command{
		Use:   "tollgate",
		Short: "Security proxy for MCP tool calls",
		Long: `Tollgate sits between an MCP client (Claude Desktop, Cursor, your own agent)
and an upstream MCP server. Every tool call is attributed to a named agent,
checked against Cedar policy, optionally sent to a human for approval,
recorded in a tamper-evident audit log, and can be stopped with a kill switch.

Tollgate's own logs go to stderr. Stdout is reserved for MCP protocol traffic.

Get started:
  tollgate init                 write tollgate.yaml, a starter policy, and a signing key
  tollgate wrap -- SERVER ...   proxy a stdio MCP server
  tollgate logs                 see decisions
  tollgate verify               check the audit log has not been tampered with`,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	cmd.PersistentFlags().StringVar(&flags.logLevel, "log-level", "info",
		"log level for Tollgate's stderr logs: debug, info, warn, error")
	cmd.PersistentFlags().StringVarP(&flags.configPath, "config", "c", "",
		"path to tollgate.yaml (default: $TOLLGATE_CONFIG, else ./tollgate.yaml)")

	cmd.AddCommand(
		newInitCmd(flags), newWrapCmd(flags), newServeCmd(flags), newCheckCmd(flags),
		newVerifyCmd(flags), newLogsCmd(flags), newExportCmd(flags),
		newKillCmd(flags), newResumeCmd(flags), newStatusCmd(flags),
		newApprovalsCmd(flags), newPinsCmd(flags), newTokenCmd(),
		newVersionCmd(),
	)
	return cmd
}

// newLogger builds the stderr logger. It never writes to stdout.
func (f *rootFlags) newLogger() (*slog.Logger, error) {
	var level slog.Level
	if err := level.UnmarshalText([]byte(strings.ToLower(f.logLevel))); err != nil {
		return nil, fmt.Errorf("invalid --log-level %q: use debug, info, warn, or error", f.logLevel)
	}
	h := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})
	return slog.New(h).With("component", "tollgate"), nil
}

// resolvedConfigPath applies the --config / $TOLLGATE_CONFIG / default order.
func (f *rootFlags) resolvedConfigPath() string {
	if f.configPath != "" {
		return f.configPath
	}
	if env := os.Getenv("TOLLGATE_CONFIG"); env != "" {
		return env
	}
	return "tollgate.yaml"
}

// loadConfig loads and validates the config (fail closed).
func (f *rootFlags) loadConfig() (*config.Config, error) {
	p := f.resolvedConfigPath()
	cfg, err := config.Load(p)
	if err != nil {
		if _, statErr := os.Stat(p); os.IsNotExist(statErr) {
			return nil, fmt.Errorf("no config at %s: run `tollgate init` or pass --config", p)
		}
		return nil, err
	}
	return cfg, nil
}

// actor names the human running an admin command, for the audit log.
func actor() string {
	if u, err := user.Current(); err == nil && u.Username != "" {
		return "cli:" + u.Username
	}
	return "cli"
}
