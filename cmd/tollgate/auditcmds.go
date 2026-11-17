package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/timeomy/tollgate/internal/audit"
	"github.com/timeomy/tollgate/internal/store"
)

// logLocation resolves the audit log and public key from flags or config.
type logLocation struct {
	log, pubkey string
}

func (l *logLocation) register(cmd *cobra.Command, withKey bool) {
	cmd.Flags().StringVar(&l.log, "log", "", "audit database (default: audit.path in config)")
	if withKey {
		cmd.Flags().StringVar(&l.pubkey, "pubkey", "", "Ed25519 public key PEM (default: <audit.signing_key>.pub)")
	}
}

func (l *logLocation) resolve(root *rootFlags, needKey bool) error {
	if l.log != "" && (!needKey || l.pubkey != "") {
		return nil
	}
	cfg, err := root.loadConfig()
	if err != nil {
		return fmt.Errorf("%w (or pass --log%s)", err, map[bool]string{true: " and --pubkey", false: ""}[needKey])
	}
	if l.log == "" {
		l.log = cfg.Audit.Path
	}
	if needKey && l.pubkey == "" {
		l.pubkey = cfg.PublicKeyPath()
	}
	return nil
}

func (l *logLocation) open(ctx context.Context) (*sql.DB, error) {
	return store.OpenReadOnly(ctx, l.log)
}

func newVerifyCmd(root *rootFlags) *cobra.Command {
	var loc logLocation
	var sealed bool
	var expect []string
	cmd := &cobra.Command{
		Use:   "verify",
		Short: "Verify the audit log's hash chain and checkpoint signatures",
		Long: `verify recomputes every event hash and checks every signed checkpoint.
It exits non-zero if a row was modified, deleted, or reordered, if a
checkpoint signature is invalid, or if the log was truncated below its
latest checkpoint.

Only the public key is needed, so an auditor can verify a copy of the log
without access to the signing key. verify never writes to the log.

Events after the last checkpoint ("unsealed") are covered by the hash chain
but not yet by a signature; --require-sealed makes them an error. Tollgate
writes a checkpoint on clean shutdown and on kill/resume.

The log cannot prove on its own that it was not rolled back to an earlier
checkpoint by someone with write access to it. verify prints an "anchor"
(seq:hash of the latest checkpoint): record it outside the state directory
and pass it back with --expect to detect a rollback or rewrite past it.
For the same reason, verify with a copy of the public key kept outside the
state directory, not the .pub file next to the signing key.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := loc.resolve(root, true); err != nil {
				return err
			}
			pub, err := audit.LoadPublicKey(loc.pubkey)
			if err != nil {
				return err
			}
			db, err := loc.open(cmd.Context())
			if err != nil {
				return err
			}
			defer db.Close()
			anchors := make([]audit.Anchor, 0, len(expect))
			for _, s := range expect {
				a, err := audit.ParseAnchor(s)
				if err != nil {
					return err
				}
				anchors = append(anchors, a)
			}
			rep, err := audit.Verify(cmd.Context(), db, audit.VerifyOptions{PublicKey: pub, RequireSealed: sealed, Expect: anchors})
			if err != nil {
				return err
			}
			printReport(cmd.OutOrStdout(), loc.log, audit.KeyID(pub), rep)
			if !rep.OK() {
				return errors.New("audit log verification FAILED")
			}
			return nil
		},
	}
	loc.register(cmd, true)
	cmd.Flags().BoolVar(&sealed, "require-sealed", false, "fail if events exist after the last checkpoint")
	cmd.Flags().StringArrayVar(&expect, "expect", nil, "anchor `SEQ:HASH` from an earlier verify that the log must still contain (repeatable)")
	return cmd
}

func printReport(w io.Writer, path, keyID string, rep audit.Report) {
	fmt.Fprintf(w, "log:          %s\n", path)
	fmt.Fprintf(w, "key id:       %s\n", keyID)
	fmt.Fprintf(w, "events:       %d (last seq %d)\n", rep.Events, rep.LastSeq)
	fmt.Fprintf(w, "checkpoints:  %d (last covers seq %d)\n", rep.Checkpoints, rep.LastCheckpointSeq)
	fmt.Fprintf(w, "unsealed:     %d\n", rep.Unsealed)
	if rep.Anchor != "" {
		fmt.Fprintf(w, "anchor:       %s\n", rep.Anchor)
	}
	if rep.OK() {
		fmt.Fprintln(w, "result:       OK - hash chain and signatures verified")
		return
	}
	fmt.Fprintln(w, "result:       FAILED")
	for _, p := range rep.Problems {
		fmt.Fprintf(w, "  - %s\n", clean(p))
	}
}

func newLogsCmd(root *rootFlags) *cobra.Command {
	var loc logLocation
	var f audit.Filter
	var since string
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "logs",
		Short: "Show audit events",
		Long:  "logs prints audit events, oldest first. Arguments appear only in redacted form.",
		Example: `  tollgate logs --decision deny
  tollgate logs --agent research-bot --since 1h --json`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := loc.resolve(root, false); err != nil {
				return err
			}
			if since != "" {
				t, err := parseSince(since)
				if err != nil {
					return err
				}
				f.Since = t
			}
			db, err := loc.open(cmd.Context())
			if err != nil {
				return err
			}
			defer db.Close()
			evs, err := audit.Query(cmd.Context(), db, f)
			if err != nil {
				return err
			}
			if asJSON {
				enc := json.NewEncoder(cmd.OutOrStdout())
				for _, e := range evs {
					if err := enc.Encode(e); err != nil {
						return err
					}
				}
				return nil
			}
			printEvents(cmd.OutOrStdout(), evs)
			return nil
		},
	}
	loc.register(cmd, false)
	cmd.Flags().StringVar(&f.Agent, "agent", "", "only this agent")
	cmd.Flags().StringVar(&f.Tool, "tool", "", "only this tool")
	cmd.Flags().StringVar(&f.Kind, "kind", "", "only this kind: tool_call, tool_result, kill, resume, pin_change, pin_accept, session")
	cmd.Flags().StringVar(&f.Decision, "decision", "", "only this decision: allow, deny")
	cmd.Flags().StringVar(&since, "since", "", "only events after a duration ago (1h) or an RFC 3339 time")
	cmd.Flags().IntVar(&f.Limit, "limit", 50, "most recent N events (0 = all)")
	cmd.Flags().BoolVar(&asJSON, "json", false, "print JSON lines")
	return cmd
}

func parseSince(s string) (time.Time, error) {
	if d, err := time.ParseDuration(s); err == nil {
		return time.Now().Add(-d), nil
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}, fmt.Errorf("--since %q: use a duration like 1h or an RFC 3339 time", s)
	}
	return t, nil
}

func printEvents(w io.Writer, evs []audit.Event) {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "SEQ\tTIME (UTC)\tKIND\tAGENT\tTOOL\tDECISION\tREASON\tARGS")
	for _, e := range evs {
		args := []rune(clean(e.ArgsPreview))
		if len(args) > 60 {
			args = append(args[:57], []rune("...")...)
		}
		fmt.Fprintf(tw, "%d\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", e.Seq, e.Time.Format("2006-01-02 15:04:05"),
			e.Kind, clean(e.Agent), clean(e.Tool), dash(clean(e.Decision)), dash(clean(e.Reason)),
			strings.ReplaceAll(string(args), "\t", " "))
	}
	_ = tw.Flush()
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func newExportCmd(root *rootFlags) *cobra.Command {
	var loc logLocation
	var out string
	cmd := &cobra.Command{
		Use:   "export",
		Short: "Export the audit log as JSON Lines",
		Long: `export writes every event and checkpoint, with their hashes and signatures,
as JSON Lines. Arguments are already redacted in the log.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := loc.resolve(root, false); err != nil {
				return err
			}
			db, err := loc.open(cmd.Context())
			if err != nil {
				return err
			}
			defer db.Close()
			w := cmd.OutOrStdout()
			if out != "" && out != "-" {
				f, err := os.OpenFile(out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
				if err != nil {
					return fmt.Errorf("export: %w (export never overwrites a file)", err)
				}
				defer f.Close()
				w = f
			}
			n, err := audit.Export(cmd.Context(), db, w)
			if err != nil {
				return err
			}
			if out != "" && out != "-" {
				fmt.Fprintf(cmd.ErrOrStderr(), "exported %d events to %s\n", n, out)
			}
			return nil
		},
	}
	loc.register(cmd, false)
	cmd.Flags().StringVarP(&out, "out", "o", "-", "output file (- for stdout)")
	return cmd
}
