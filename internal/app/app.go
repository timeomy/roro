// Package app assembles Tollgate's components from a config. Every step is
// fail-closed: if policy, identity, state, or the audit log cannot be
// initialised, Open returns an error and no traffic is proxied.
package app

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/timeomy/tollgate/internal/approval"
	"github.com/timeomy/tollgate/internal/audit"
	"github.com/timeomy/tollgate/internal/config"
	"github.com/timeomy/tollgate/internal/gate"
	"github.com/timeomy/tollgate/internal/killswitch"
	"github.com/timeomy/tollgate/internal/observe"
	"github.com/timeomy/tollgate/internal/pin"
	"github.com/timeomy/tollgate/internal/policy"
	"github.com/timeomy/tollgate/internal/store"
)

// Runtime holds the shared components for a proxy process.
type Runtime struct {
	Config    *config.Config
	State     *sql.DB
	Audit     *audit.HashChainSQLiteLog
	Kill      *killswitch.Switch
	Pins      *pin.Store
	Approver  *approval.CLIApprover
	Engine    *policy.CedarEngine
	Matchers  []policy.Matcher
	Rates     *policy.RateCounter
	Telemetry *observe.Telemetry
	Logger    *slog.Logger
}

// StateSchema is the full schema of the state database.
func StateSchema() []string {
	var s []string
	s = append(s, killswitch.Schema...)
	s = append(s, pin.Schema...)
	s = append(s, approval.Schema...)
	return s
}

// OpenState opens the state database.
func OpenState(ctx context.Context, cfg *config.Config) (*sql.DB, error) {
	return store.Open(ctx, cfg.StateDB(), StateSchema()...)
}

// OpenAudit opens the audit log for writing with the configured key.
func OpenAudit(ctx context.Context, cfg *config.Config) (*audit.HashChainSQLiteLog, error) {
	signer, err := audit.LoadSigner(cfg.Audit.SigningKey)
	if err != nil {
		return nil, err
	}
	return audit.OpenLog(ctx, audit.Options{Path: cfg.Audit.Path, Signer: signer, CheckpointEvery: cfg.Audit.CheckpointEvery})
}

// LoadPolicy compiles matchers and Cedar policies.
func LoadPolicy(cfg *config.Config) (*policy.CedarEngine, []policy.Matcher, error) {
	matchers := make([]policy.Matcher, 0, len(cfg.Matchers))
	for _, m := range cfg.Matchers {
		pm, err := policy.NewMatcher(m.Name, m.Regex)
		if err != nil {
			return nil, nil, err
		}
		matchers = append(matchers, pm)
	}
	engine, err := policy.LoadCedar(cfg.Policy.Files, policy.MatcherNames(matchers))
	if err != nil {
		return nil, nil, err
	}
	return engine, matchers, nil
}

// Open builds a Runtime for wrap/serve.
func Open(ctx context.Context, cfg *config.Config, logger *slog.Logger, version string) (*Runtime, error) {
	r := &Runtime{Config: cfg, Logger: logger, Rates: policy.NewRateCounter()}
	var err error
	if r.Engine, r.Matchers, err = LoadPolicy(cfg); err != nil {
		return nil, err
	}
	if r.Audit, err = OpenAudit(ctx, cfg); err != nil {
		return nil, err
	}
	if r.State, err = OpenState(ctx, cfg); err != nil {
		_ = r.Audit.Close()
		return nil, err
	}
	r.Kill = killswitch.New(r.State)
	r.Pins = pin.New(r.State)
	r.Approver = approval.NewCLIApprover(r.State)
	r.Telemetry, err = observe.Setup(ctx, observe.Config{
		Endpoint: cfg.Telemetry.OTLPEndpoint, Insecure: cfg.Telemetry.Insecure,
		ServiceName: cfg.Telemetry.ServiceName, Version: version,
	})
	if err != nil {
		_ = r.Close()
		return nil, err
	}
	logger.Info("tollgate ready", "mode", cfg.Mode, "policies", r.Engine.PolicyCount(),
		"audit", cfg.Audit.Path, "state", cfg.StateDB())
	return r, nil
}

// Deps returns gate dependencies backed by this runtime.
func (r *Runtime) Deps() gate.Deps {
	return gate.Deps{
		Policy: r.Engine, Matchers: r.Matchers, Rates: r.Rates, Audit: r.Audit,
		Kill: r.Kill, Pins: r.Pins, Approver: r.Approver, Telemetry: r.Telemetry,
		Mode: r.Config.Mode, PinOnChange: r.Config.Pinning.OnChange,
		ApprovalTimeout: r.Config.Approval.Timeout.Duration, Logger: r.Logger,
	}
}

// Close checkpoints the audit log and releases everything.
func (r *Runtime) Close() error {
	var errs []error
	if r.Telemetry != nil {
		errs = append(errs, r.Telemetry.Shutdown(context.Background()))
	}
	if r.Audit != nil {
		errs = append(errs, r.Audit.Close())
	}
	if r.State != nil {
		errs = append(errs, r.State.Close())
	}
	return errors.Join(errs...)
}

var unsafeName = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

// ServerName picks the upstream name used in policy and pins: the configured
// name, else the command's base name.
func ServerName(cfg *config.Config, command []string) (string, error) {
	if cfg.Upstream.Name != "" {
		return cfg.Upstream.Name, nil
	}
	if len(command) == 0 {
		return "", fmt.Errorf("upstream.name is required when no upstream command is given")
	}
	base := strings.TrimSuffix(filepath.Base(command[0]), filepath.Ext(command[0]))
	name := strings.Trim(unsafeName.ReplaceAllString(base, "-"), "-.")
	if name == "" {
		return "", fmt.Errorf("cannot derive a server name from %q; set upstream.name", command[0])
	}
	if len(name) > 64 {
		name = name[:64]
	}
	return name, nil
}
