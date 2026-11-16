package main

import (
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

type rootFlags struct {
	logLevel string
}

func newRootCmd() *cobra.Command {
	flags := &rootFlags{}
	cmd := &cobra.Command{
		Use:   "tollgate",
		Short: "Security proxy for MCP tool calls",
		Long: `Tollgate sits between an MCP client (Claude Desktop, Cursor, your own agent)
and an upstream MCP server. Every message passes through Tollgate, which is
where per-agent policy, human approval, audit logging, and the kill switch
are enforced.

Tollgate's own logs go to stderr. Stdout is reserved for MCP protocol traffic.`,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	cmd.PersistentFlags().StringVar(&flags.logLevel, "log-level", "info",
		"log level for Tollgate's stderr logs: debug, info, warn, error")

	cmd.AddCommand(newWrapCmd(flags), newVersionCmd())
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
