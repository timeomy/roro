package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/timeomy/tollgate/internal/audit"
	"github.com/timeomy/tollgate/internal/identity"
	"github.com/timeomy/tollgate/policies"
)

const configTemplate = `# Tollgate configuration. Runtime wiring only: authorization rules live in
# the Cedar files listed under policy.files.
version: 1

# enforce: deny what policy denies. monitor: log what policy would deny, but
# forward anyway (the kill switch still applies).
mode: enforce

# Kill switch, pins, approval queue, audit log, and signing key live here.
state_dir: .tollgate

# Default agent identity for "tollgate wrap". Override per MCP client with
# --agent or $TOLLGATE_AGENT, e.g. one name for Cursor and one for Claude.
agent:
  name: %s
  client: ""
  owner: ""

upstream:
  # Name used in policy (resource.server) and pins. Defaults to the command's
  # base name. Set it when one config wraps several servers.
  name: ""
  # Default upstream for "tollgate serve" (wrap takes the command after --).
  command: []

policy:
  files:
    - policies/tollgate.cedar

# Named regular expressions tested against every string argument. Each one
# becomes context.matches.<name> in Cedar; policy decides what it means.
matchers:
  - name: aws_access_key
    regex: '\b(AKIA|ASIA)[0-9A-Z]{16}\b'
  - name: private_key_block
    regex: '-----BEGIN [A-Z ]*PRIVATE KEY-----'

approval:
  # A require-approval call waits this long for "tollgate approvals"; then it
  # is denied.
  timeout: 2m

pinning:
  # block: hide changed tools and deny calls until "tollgate pins accept".
  # alert: log the change and let it through.
  on_change: block

audit:
  checkpoint_every: 100

http:
  listen: 127.0.0.1:8787
  # agents:
  #   - name: research-bot
  #     token_sha256: <from "tollgate token new --agent research-bot">

telemetry:
  # OTLP/HTTP collector, e.g. localhost:4318. Empty disables export.
  otlp_endpoint: ""
  insecure: true
`

func newInitCmd(root *rootFlags) *cobra.Command {
	var dir, sandbox, agent string
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Write a starter config, policy, and audit signing key",
		Long: `init creates, in --dir:

  tollgate.yaml                     runtime config
  policies/tollgate.cedar           starter Cedar policy (paths scoped to --sandbox)
  .tollgate/audit-signing.key       Ed25519 private key for audit checkpoints (0600)
  .tollgate/audit-signing.key.pub   public key for "tollgate verify"

It never overwrites an existing file. Keep the private key out of version
control; anyone holding it can sign checkpoints.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runInit(cmd, dir, sandbox, agent)
		},
	}
	cmd.Flags().StringVar(&dir, "dir", ".", "directory to initialise")
	cmd.Flags().StringVar(&sandbox, "sandbox", "./sandbox", "directory file tools may read and write (absolute in the policy)")
	cmd.Flags().StringVar(&agent, "agent", "my-agent", "default agent name")
	return cmd
}

func runInit(cmd *cobra.Command, dir, sandbox, agent string) error {
	if err := (identity.Agent{Name: agent}).Validate(); err != nil {
		return err
	}
	absDir, err := filepath.Abs(dir)
	if err != nil {
		return err
	}
	sb := sandbox
	if !filepath.IsAbs(sb) {
		sb = filepath.Join(absDir, sb)
	}
	sb = filepath.ToSlash(filepath.Clean(sb))
	if strings.ContainsAny(sb, `"*\`) {
		return fmt.Errorf("sandbox path %q must not contain quotes, '*' or backslashes", sb)
	}
	cfgPath := filepath.Join(absDir, "tollgate.yaml")
	polPath := filepath.Join(absDir, "policies", "tollgate.cedar")
	keyPath := filepath.Join(absDir, ".tollgate", "audit-signing.key")
	for _, p := range []string{cfgPath, polPath, keyPath} {
		if _, err := os.Stat(p); err == nil {
			return fmt.Errorf("%s already exists; init never overwrites files", p)
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	if err := os.MkdirAll(filepath.Dir(polPath), 0o755); err != nil {
		return err
	}
	if err := os.MkdirAll(sb, 0o755); err != nil {
		return fmt.Errorf("create sandbox: %w", err)
	}
	policy := strings.ReplaceAll(policies.Starter, `"`+policies.SandboxPlaceholder+`/*"`, `"`+sb+`/*"`)
	if err := os.WriteFile(polPath, []byte(policy), 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(cfgPath, fmt.Appendf(nil, configTemplate, agent), 0o644); err != nil {
		return err
	}
	keyID, err := audit.GenerateKey(keyPath)
	if err != nil {
		return err
	}
	out := cmd.OutOrStdout()
	fmt.Fprintf(out, "wrote %s\nwrote %s (sandbox %s)\nwrote %s (key id %s)\n", cfgPath, polPath, sb, keyPath, keyID)
	fmt.Fprintf(out, "\nNext: tollgate --config %s check\n", cfgPath)
	return nil
}
