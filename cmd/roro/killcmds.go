package main

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/timeomy/roro/internal/app"
	"github.com/timeomy/roro/internal/approval"
	"github.com/timeomy/roro/internal/audit"
	"github.com/timeomy/roro/internal/identity"
	"github.com/timeomy/roro/internal/killswitch"
	"github.com/timeomy/roro/internal/pin"
)

func newKillCmd(root *rootFlags) *cobra.Command {
	return switchCmd(root, true)
}

func newResumeCmd(root *rootFlags) *cobra.Command {
	return switchCmd(root, false)
}

func switchCmd(root *rootFlags, kill bool) *cobra.Command {
	var agent, reason string
	use, short, long := "resume", "Resume tool calls after a kill", `resume clears the global kill switch, or with --agent, one agent's switch.
Resuming the global switch does not clear per-agent switches. The resume is
recorded in the audit log.`
	if kill {
		use, short, long = "kill", "Stop all tool calls, globally or for one agent", `kill activates the kill switch. Every running Roro process that shares
this state directory denies the next tool call (reason kill_switch_active),
and the switch survives restarts until "roro resume". The kill is
recorded and checkpointed in the audit log.`
	}
	cmd := &cobra.Command{
		Use: use, Short: short, Long: long, Args: cobra.NoArgs,
		Example: fmt.Sprintf("  roro %s\n  roro %s --agent research-bot --reason \"investigating\"", use, use),
		RunE: func(cmd *cobra.Command, _ []string) error {
			if agent != "" {
				if err := (identity.Agent{Name: agent}).Validate(); err != nil {
					return err
				}
			}
			return runSwitch(cmd, root, kill, agent, reason)
		},
	}
	cmd.Flags().StringVar(&agent, "agent", "", "only this agent (default: global)")
	cmd.Flags().StringVar(&reason, "reason", "", "why (recorded in the audit log)")
	return cmd
}

func runSwitch(cmd *cobra.Command, root *rootFlags, kill bool, agent, reason string) error {
	ctx := cmd.Context()
	cfg, err := root.loadConfig()
	if err != nil {
		return err
	}
	// Open the audit log first, so a broken log is found before acting.
	log, err := app.OpenAudit(ctx, cfg)
	if err != nil {
		return err
	}
	defer log.Close()
	db, err := app.OpenState(ctx, cfg)
	if err != nil {
		return err
	}
	defer db.Close()
	sw := killswitch.New(db)
	who := actor()
	record := func(kind string) error {
		_, err := log.Append(ctx, audit.Event{Kind: kind, Agent: agent, Reason: killswitch.Scope(agent),
			Detail: fmt.Sprintf("by=%s reason=%s", who, reason)})
		return err
	}
	// Order is chosen so a failure leaves agents stopped: a kill takes
	// effect even if it cannot be recorded (the error is still reported);
	// a resume that cannot be recorded is not done.
	if kill {
		if err := sw.Kill(ctx, agent, reason, who); err != nil {
			return err
		}
		if err := record(audit.KindKill); err != nil {
			return fmt.Errorf("kill switch is ON, but the audit log could not record it: %w", err)
		}
	} else {
		if err := record(audit.KindResume); err != nil {
			return fmt.Errorf("not resumed: the audit log could not record it: %w", err)
		}
		if err := sw.Resume(ctx, agent, reason, who); err != nil {
			return err
		}
	}
	if err := log.Checkpoint(ctx); err != nil {
		return err
	}
	target := "all agents"
	if agent != "" {
		target = "agent " + agent
	}
	fmt.Fprintf(cmd.OutOrStdout(), "%s: %s\n", map[bool]string{true: "killed", false: "resumed"}[kill], target)
	return nil
}

func newStatusCmd(root *rootFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show kill switches, pending approvals, and changed tools",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := root.loadConfig()
			if err != nil {
				return err
			}
			db, err := app.OpenState(cmd.Context(), cfg)
			if err != nil {
				return err
			}
			defer db.Close()
			return printStatus(cmd.Context(), cmd, db, cfg.Mode)
		},
	}
}

func printStatus(ctx context.Context, cmd *cobra.Command, sdb *sql.DB, mode string) error {
	out := cmd.OutOrStdout()
	fmt.Fprintf(out, "mode: %s\n", mode)
	entries, err := killswitch.New(sdb).List(ctx)
	if err != nil {
		return err
	}
	var active []string
	for _, e := range entries {
		if e.Active {
			active = append(active, fmt.Sprintf("%s (by %s: %s)", clean(e.Scope), clean(e.Actor), clean(e.Reason)))
		}
	}
	if len(active) == 0 {
		fmt.Fprintln(out, "kill switch: off")
	} else {
		fmt.Fprintf(out, "kill switch: ON for %s\n", strings.Join(active, "; "))
	}
	pending, err := approval.Pending(ctx, sdb)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "pending approvals: %d\n", len(pending))
	pins, err := pin.New(sdb).List(ctx)
	if err != nil {
		return err
	}
	changed := 0
	for _, p := range pins {
		if p.PendingHash != "" {
			changed++
		}
	}
	fmt.Fprintf(out, "pinned tools: %d (%d changed, awaiting review)\n", len(pins), changed)
	return nil
}
