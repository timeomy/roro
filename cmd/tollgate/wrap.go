package main

import (
	"errors"

	"github.com/spf13/cobra"

	"github.com/timeomy/tollgate/internal/proxy"
)

func newWrapCmd(root *rootFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "wrap [flags] -- COMMAND [ARGS...]",
		Short: "Proxy a local stdio MCP server",
		Long: `wrap starts COMMAND as the upstream MCP server and relays MCP traffic
between it and the client on Tollgate's own stdin/stdout.

Use it as a drop-in replacement for the server command in an MCP client
config: put "tollgate" as the command and "wrap", "--", followed by the
original command and arguments, as the args.

The upstream server's stderr is passed through to Tollgate's stderr.
Tollgate exits with status 0 when the client disconnects and non-zero if the
upstream server exits first.`,
		Example: `  tollgate wrap -- npx -y @modelcontextprotocol/server-filesystem /tmp/sandbox
  tollgate wrap --log-level debug -- /usr/local/bin/my-mcp-server --verbose`,
		Args: func(cmd *cobra.Command, args []string) error {
			if cmd.ArgsLenAtDash() != 0 || len(args) == 0 {
				return errors.New(`give the upstream server command after "--", for example: tollgate wrap -- my-mcp-server`)
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			logger, err := root.newLogger()
			if err != nil {
				return err
			}
			logger.Info("starting stdio proxy", "upstream", args[0])
			err = proxy.RunStdio(cmd.Context(), proxy.StdioOptions{
				Command: args[0],
				Args:    args[1:],
				Logger:  logger,
			})
			if err != nil {
				return err
			}
			logger.Info("client disconnected; proxy stopped")
			return nil
		},
	}
}
