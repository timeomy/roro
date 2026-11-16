package main

import (
	"database/sql"
	"fmt"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/timeomy/tollgate/internal/app"
	"github.com/timeomy/tollgate/internal/audit"
	"github.com/timeomy/tollgate/internal/identity"
	"github.com/timeomy/tollgate/internal/pin"
)

func newPinsCmd(root *rootFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "pins",
		Short: "Review pinned tool definitions",
		Long: `Tollgate pins each tool's name, description, and schemas the first time it is
listed. A later change marks the tool "changed"; with pinning.on_change: block
it is hidden and its calls are denied until you accept the new definition.`,
	}
	list := &cobra.Command{
		Use: "list", Short: "List pinned tools", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return withState(root, cmd.Context(), func(db *sql.DB) error {
				pins, err := pin.New(db).List(cmd.Context())
				if err != nil {
					return err
				}
				tw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
				fmt.Fprintln(tw, "SERVER\tTOOL\tSTATUS\tHASH\tFIRST SEEN")
				for _, p := range pins {
					st := pin.StatusPinned
					if p.PendingHash != "" {
						st = pin.StatusChanged + " -> " + p.PendingHash[:12]
					}
					fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", p.Server, p.Tool, st, p.Hash[:12], p.FirstSeen)
				}
				return tw.Flush()
			})
		},
	}
	var server, tool string
	accept := &cobra.Command{
		Use:   "accept --server NAME --tool NAME",
		Short: "Accept a changed tool definition",
		Long:  "accept makes the changed definition the new pin. Read the new description first: a changed description is a known prompt-injection channel.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := root.loadConfig()
			if err != nil {
				return err
			}
			log, err := app.OpenAudit(cmd.Context(), cfg)
			if err != nil {
				return err
			}
			defer log.Close()
			return withState(root, cmd.Context(), func(db *sql.DB) error {
				c, err := pin.New(db).Accept(cmd.Context(), server, tool)
				if err != nil {
					return err
				}
				_, err = log.Append(cmd.Context(), audit.Event{Kind: audit.KindPinAccept, Server: server, Tool: tool,
					Reason: "tool_accepted", Detail: fmt.Sprintf("by=%s old=%s new=%s", actor(), c.OldHash, c.NewHash)})
				if err != nil {
					return err
				}
				fmt.Fprintf(cmd.OutOrStdout(), "accepted %s/%s (%s)\n", server, tool, c.NewHash[:12])
				return nil
			})
		},
	}
	accept.Flags().StringVar(&server, "server", "", "upstream server name")
	accept.Flags().StringVar(&tool, "tool", "", "tool name")
	_ = accept.MarkFlagRequired("server")
	_ = accept.MarkFlagRequired("tool")
	cmd.AddCommand(list, accept)
	return cmd
}

func newTokenCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "token", Short: "Manage bearer tokens for HTTP agents"}
	var agent string
	gen := &cobra.Command{
		Use:   "new --agent NAME",
		Short: "Create a bearer token for an HTTP agent",
		Long: `new prints a fresh random token and the config entry for it. Give the token
to the agent's MCP client; put only the token_sha256 line in tollgate.yaml.
The token is shown once and is not stored anywhere by Tollgate.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := (identity.Agent{Name: agent}).Validate(); err != nil {
				return err
			}
			token, digest, err := identity.NewToken()
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "token (give to the client, shown once):\n  %s\n\n", token)
			fmt.Fprintf(out, "add to tollgate.yaml under http.agents:\n  - name: %s\n    token_sha256: %s\n", agent, digest)
			return nil
		},
	}
	gen.Flags().StringVar(&agent, "agent", "", "agent name")
	_ = gen.MarkFlagRequired("agent")
	cmd.AddCommand(gen)
	return cmd
}

func newCheckCmd(root *rootFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "check",
		Short: "Validate the config, policies, and signing key without proxying",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := root.loadConfig()
			if err != nil {
				return err
			}
			engine, matchers, err := app.LoadPolicy(cfg)
			if err != nil {
				return err
			}
			signer, err := audit.LoadSigner(cfg.Audit.SigningKey)
			if err != nil {
				return err
			}
			if _, err := audit.LoadPublicKey(cfg.PublicKeyPath()); err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "config:    %s (mode %s)\n", cfg.Path(), cfg.Mode)
			fmt.Fprintf(out, "policies:  %d loaded from %d file(s), %d matcher(s)\n", engine.PolicyCount(), len(cfg.Policy.Files), len(matchers))
			fmt.Fprintf(out, "audit:     %s (key id %s)\n", cfg.Audit.Path, signer.KeyID())
			fmt.Fprintf(out, "state:     %s\n", cfg.StateDB())
			fmt.Fprintln(out, "OK")
			return nil
		},
	}
}
