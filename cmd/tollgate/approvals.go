package main

import (
	"bufio"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/timeomy/tollgate/internal/app"
	"github.com/timeomy/tollgate/internal/approval"
)

func newApprovalsCmd(root *rootFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "approvals",
		Short: "Review tool calls waiting for human approval",
		Long: `When policy marks a call require-approval, the proxy queues it and waits
(approval.timeout; no answer means deny). Answer from any terminal:

  tollgate approvals watch           prompt for each request as it arrives
  tollgate approvals list            show pending requests
  tollgate approvals approve ID      allow one request
  tollgate approvals deny ID         deny one request

Requests show the raw tool name and arguments the agent sent (secrets
redacted), not a model-written summary. Approve only what you would run
yourself.`,
	}
	cmd.AddCommand(approvalsList(root), approvalsDecide(root, true), approvalsDecide(root, false), approvalsWatch(root))
	return cmd
}

func withState(root *rootFlags, ctx context.Context, fn func(*sql.DB) error) error {
	cfg, err := root.loadConfig()
	if err != nil {
		return err
	}
	db, err := app.OpenState(ctx, cfg)
	if err != nil {
		return err
	}
	defer db.Close()
	return fn(db)
}

func approvalsList(root *rootFlags) *cobra.Command {
	return &cobra.Command{
		Use: "list", Short: "List pending approval requests", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return withState(root, cmd.Context(), func(db *sql.DB) error {
				reqs, err := approval.Pending(cmd.Context(), db)
				if err != nil {
					return err
				}
				if len(reqs) == 0 {
					fmt.Fprintln(cmd.OutOrStdout(), "no pending approvals")
				}
				for _, r := range reqs {
					printRequest(cmd.OutOrStdout(), r)
				}
				return nil
			})
		},
	}
}

func approvalsDecide(root *rootFlags, approve bool) *cobra.Command {
	use, short := "deny ID", "Deny a pending request"
	if approve {
		use, short = "approve ID", "Approve a pending request"
	}
	return &cobra.Command{
		Use: use, Short: short, Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withState(root, cmd.Context(), func(db *sql.DB) error {
				if err := approval.Decide(cmd.Context(), db, args[0], approve, actor()); err != nil {
					return err
				}
				fmt.Fprintf(cmd.OutOrStdout(), "%s %s\n", map[bool]string{true: "approved", false: "denied"}[approve], args[0])
				return nil
			})
		},
	}
}

func approvalsWatch(root *rootFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "watch",
		Short: "Prompt for each approval request as it arrives",
		Long:  "watch polls for pending requests and asks y/N for each. Anything but y or yes denies. Ctrl-C to stop.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return withState(root, cmd.Context(), func(db *sql.DB) error {
				return watchLoop(cmd.Context(), db, cmd.InOrStdin(), cmd.OutOrStdout())
			})
		},
	}
}

func watchLoop(ctx context.Context, db *sql.DB, in io.Reader, out io.Writer) error {
	lines := make(chan string)
	go func() {
		sc := bufio.NewScanner(in)
		for sc.Scan() {
			lines <- sc.Text()
		}
		close(lines)
	}()
	fmt.Fprintln(out, "watching for approval requests (Ctrl-C to stop)...")
	seen := map[string]bool{}
	tick := time.NewTicker(500 * time.Millisecond)
	defer tick.Stop()
	for {
		reqs, err := approval.Pending(ctx, db)
		if err != nil {
			return err
		}
		for _, r := range reqs {
			if seen[r.ID] {
				continue
			}
			seen[r.ID] = true
			printRequest(out, r)
			fmt.Fprintf(out, "approve %s? [y/N] ", r.ID)
			var answer string
			select {
			case <-ctx.Done():
				return nil
			case l, ok := <-lines:
				if !ok {
					return errors.New("stdin closed")
				}
				answer = strings.ToLower(strings.TrimSpace(l))
			}
			approve := answer == "y" || answer == "yes"
			if err := approval.Decide(ctx, db, r.ID, approve, actor()); err != nil {
				fmt.Fprintf(out, "  could not record decision: %v\n", err)
				continue
			}
			fmt.Fprintf(out, "  %s\n\n", map[bool]string{true: "APPROVED", false: "DENIED"}[approve])
		}
		select {
		case <-ctx.Done():
			return nil
		case <-tick.C:
		}
	}
}

func printRequest(w io.Writer, r approval.Request) {
	fmt.Fprintf(w, "\n=== approval %s ===\n", r.ID)
	fmt.Fprintf(w, "agent:    %s\n", r.Agent)
	fmt.Fprintf(w, "server:   %s\n", r.Server)
	fmt.Fprintf(w, "tool:     %s\n", r.Tool)
	fmt.Fprintf(w, "policy:   %s (%s)\n", r.Reason, strings.Join(r.PolicyIDs, ", "))
	fmt.Fprintf(w, "expires:  %s (in %s)\n", r.Expires.Local().Format(time.TimeOnly), time.Until(r.Expires).Round(time.Second))
	fmt.Fprintf(w, "arguments (exactly as sent, secrets redacted):\n%s\n", indent(r.ArgsJSON))
}

func indent(s string) string {
	return "  " + strings.ReplaceAll(s, "\n", "\n  ")
}
