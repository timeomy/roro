// Package config loads and validates roro.yaml.
//
// YAML holds runtime wiring only: where state lives, which policy files to
// load, timeouts, listeners, and telemetry endpoints. Authorization logic
// lives in Cedar policy files. Loading is strict: unknown keys, bad values,
// and missing files are errors, and Roro refuses to proxy without a valid
// configuration (fail closed).
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"go.yaml.in/yaml/v3"
)

// Modes.
const (
	ModeEnforce = "enforce"
	ModeMonitor = "monitor"
)

// Pin change actions.
const (
	PinBlock = "block"
	PinAlert = "alert"
)

// Config is the parsed roro.yaml.
type Config struct {
	Version   int             `yaml:"version"`
	Mode      string          `yaml:"mode"`
	StateDir  string          `yaml:"state_dir"`
	Agent     AgentConfig     `yaml:"agent"`
	Upstream  UpstreamConfig  `yaml:"upstream"`
	Policy    PolicyConfig    `yaml:"policy"`
	Matchers  []MatcherConfig `yaml:"matchers"`
	Approval  ApprovalConfig  `yaml:"approval"`
	Pinning   PinningConfig   `yaml:"pinning"`
	Audit     AuditConfig     `yaml:"audit"`
	HTTP      HTTPConfig      `yaml:"http"`
	Telemetry TelemetryConfig `yaml:"telemetry"`

	// path is the absolute path the config was loaded from.
	path string
}

// AgentConfig is the default agent identity for stdio mode.
type AgentConfig struct {
	Name   string `yaml:"name"`
	Client string `yaml:"client"`
	Owner  string `yaml:"owner"`
}

// UpstreamConfig describes the upstream MCP server. For `wrap`, the command
// after "--" overrides Command.
type UpstreamConfig struct {
	// Name identifies the server in policy (resource.server), pins, and logs.
	Name    string   `yaml:"name"`
	Command []string `yaml:"command"`
	// URL is a streamable HTTP upstream (serve mode only).
	URL string `yaml:"url"`
}

// PolicyConfig lists Cedar policy files.
type PolicyConfig struct {
	Files []string `yaml:"files"`
}

// MatcherConfig defines a named regular expression. Roro tests every
// string argument against it and exposes the result to Cedar as
// context.matches.<name>. The matcher itself allows or denies nothing.
type MatcherConfig struct {
	Name  string `yaml:"name"`
	Regex string `yaml:"regex"`
}

// ApprovalConfig configures human approval.
type ApprovalConfig struct {
	Timeout Duration `yaml:"timeout"`
	// MaxPending caps approval waits per Roro process; calls beyond it
	// are denied rather than queued.
	MaxPending int `yaml:"max_pending"`
}

// PinningConfig configures tool-definition pinning.
type PinningConfig struct {
	OnChange string `yaml:"on_change"`
}

// AuditConfig configures the audit log.
type AuditConfig struct {
	Path            string `yaml:"path"`
	SigningKey      string `yaml:"signing_key"`
	CheckpointEvery int    `yaml:"checkpoint_every"`
}

// HTTPConfig configures `roro serve`.
type HTTPConfig struct {
	Listen         string      `yaml:"listen"`
	AllowedOrigins []string    `yaml:"allowed_origins"`
	Agents         []HTTPAgent `yaml:"agents"`
	SessionIdle    Duration    `yaml:"session_idle_timeout"`
	MaxBodyBytes   int64       `yaml:"max_body_bytes"`
	// MaxSessions caps concurrent MCP sessions (each runs an upstream).
	MaxSessions int `yaml:"max_sessions"`
	// MaxSessionsPerAgent caps concurrent sessions per agent token.
	MaxSessionsPerAgent int            `yaml:"max_sessions_per_agent"`
	TLS                 *HTTPTLSConfig `yaml:"tls"`
}

// HTTPTLSConfig enables TLS on the listener.
type HTTPTLSConfig struct {
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
}

// HTTPAgent maps a bearer token digest to an agent identity.
type HTTPAgent struct {
	Name        string `yaml:"name"`
	Client      string `yaml:"client"`
	Owner       string `yaml:"owner"`
	TokenSHA256 string `yaml:"token_sha256"`
}

// TelemetryConfig configures OpenTelemetry export. Empty endpoint disables it.
type TelemetryConfig struct {
	OTLPEndpoint string `yaml:"otlp_endpoint"`
	Insecure     bool   `yaml:"insecure"`
	ServiceName  string `yaml:"service_name"`
}

// Duration is a time.Duration written as a Go duration string ("90s", "2m").
type Duration struct{ time.Duration }

// UnmarshalYAML parses a duration string.
func (d *Duration) UnmarshalYAML(n *yaml.Node) error {
	var s string
	if err := n.Decode(&s); err != nil {
		return fmt.Errorf("line %d: duration must be a string like \"2m\"", n.Line)
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("line %d: invalid duration %q: %w", n.Line, s, err)
	}
	d.Duration = v
	return nil
}

// MarshalYAML writes the duration string.
func (d Duration) MarshalYAML() (any, error) { return d.String(), nil }

// Load reads, defaults, resolves, and validates a config file.
func Load(path string) (*Config, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	data, err := os.ReadFile(abs)
	if err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	cfg, err := Parse(data, filepath.Dir(abs))
	if err != nil {
		return nil, fmt.Errorf("config %s: %w", abs, err)
	}
	cfg.path = abs
	return cfg, nil
}

// Parse decodes config bytes. Relative paths resolve against baseDir.
func Parse(data []byte, baseDir string) (*Config, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	var cfg Config
	if err := dec.Decode(&cfg); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, errors.New("file is empty")
		}
		return nil, err
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, errors.New("only one YAML document is allowed")
	}
	cfg.applyDefaults()
	cfg.resolvePaths(baseDir)
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// Path returns the file the config was loaded from ("" if parsed from bytes).
func (c *Config) Path() string { return c.path }

// StateDB is the runtime state database (kill switch, pins, approvals).
func (c *Config) StateDB() string { return filepath.Join(c.StateDir, "state.db") }

// PublicKeyPath is where the audit verification key is stored.
func (c *Config) PublicKeyPath() string { return c.Audit.SigningKey + ".pub" }

func (c *Config) applyDefaults() {
	if c.Mode == "" {
		c.Mode = ModeEnforce
	}
	if c.StateDir == "" {
		c.StateDir = ".roro"
	}
	if c.Approval.Timeout.Duration == 0 {
		c.Approval.Timeout.Duration = 2 * time.Minute
	}
	if c.Approval.MaxPending == 0 {
		c.Approval.MaxPending = 16
	}
	if c.HTTP.MaxSessions == 0 {
		c.HTTP.MaxSessions = 64
	}
	if c.HTTP.MaxSessionsPerAgent == 0 {
		c.HTTP.MaxSessionsPerAgent = 8
	}
	if c.Pinning.OnChange == "" {
		c.Pinning.OnChange = PinBlock
	}
	if c.Audit.CheckpointEvery == 0 {
		c.Audit.CheckpointEvery = 100
	}
	if c.HTTP.Listen == "" {
		c.HTTP.Listen = "127.0.0.1:8787"
	}
	if c.HTTP.SessionIdle.Duration == 0 {
		c.HTTP.SessionIdle.Duration = 30 * time.Minute
	}
	if c.HTTP.MaxBodyBytes == 0 {
		c.HTTP.MaxBodyBytes = 4 << 20
	}
	if c.Telemetry.ServiceName == "" {
		c.Telemetry.ServiceName = "roro"
	}
}

func (c *Config) resolvePaths(base string) {
	abs := func(p string) string {
		if p == "" || filepath.IsAbs(p) {
			return p
		}
		return filepath.Join(base, p)
	}
	c.StateDir = abs(c.StateDir)
	for i, f := range c.Policy.Files {
		c.Policy.Files[i] = abs(f)
	}
	if c.Audit.Path == "" {
		c.Audit.Path = filepath.Join(c.StateDir, "audit.db")
	}
	c.Audit.Path = abs(c.Audit.Path)
	if c.Audit.SigningKey == "" {
		c.Audit.SigningKey = filepath.Join(c.StateDir, "audit-signing.key")
	}
	c.Audit.SigningKey = abs(c.Audit.SigningKey)
	if c.HTTP.TLS != nil {
		c.HTTP.TLS.CertFile = abs(c.HTTP.TLS.CertFile)
		c.HTTP.TLS.KeyFile = abs(c.HTTP.TLS.KeyFile)
	}
}
