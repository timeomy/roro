package config

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

var (
	identPattern      = regexp.MustCompile(`^[a-z_][a-z0-9_]{0,63}$`)
	serverNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
)

// Validate checks every field and returns all problems at once.
func (c *Config) Validate() error {
	var errs []error
	add := func(format string, args ...any) { errs = append(errs, fmt.Errorf(format, args...)) }

	if c.Version != 1 {
		add("version: must be 1 (got %d)", c.Version)
	}
	if c.Mode != ModeEnforce && c.Mode != ModeMonitor {
		add("mode: must be %q or %q (got %q)", ModeEnforce, ModeMonitor, c.Mode)
	}
	if c.Upstream.Name != "" && !serverNamePattern.MatchString(c.Upstream.Name) {
		add("upstream.name: %q must be 1-64 letters, digits, '.', '_' or '-'", c.Upstream.Name)
	}
	if c.Upstream.URL != "" {
		if len(c.Upstream.Command) > 0 {
			add("upstream: set either command or url, not both")
		}
		u, err := url.Parse(c.Upstream.URL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			add("upstream.url: %q must be an http(s) URL", c.Upstream.URL)
		}
	}
	if len(c.Policy.Files) == 0 {
		add("policy.files: at least one Cedar policy file is required")
	}
	for _, f := range c.Policy.Files {
		if st, err := os.Stat(f); err != nil {
			add("policy.files: %v", err)
		} else if st.IsDir() {
			add("policy.files: %s is a directory", f)
		}
	}
	c.validateMatchers(add)
	if c.Approval.Timeout.Duration < time.Second || c.Approval.Timeout.Duration > 24*time.Hour {
		add("approval.timeout: must be between 1s and 24h (got %s)", c.Approval.Timeout)
	}
	if c.Pinning.OnChange != PinBlock && c.Pinning.OnChange != PinAlert {
		add("pinning.on_change: must be %q or %q (got %q)", PinBlock, PinAlert, c.Pinning.OnChange)
	}
	if c.Audit.CheckpointEvery < 1 || c.Audit.CheckpointEvery > 100000 {
		add("audit.checkpoint_every: must be between 1 and 100000")
	}
	c.validateHTTP(add)
	if err := c.validateAgent(); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

func (c *Config) validateMatchers(add func(string, ...any)) {
	seen := map[string]bool{}
	for i, m := range c.Matchers {
		if !identPattern.MatchString(m.Name) {
			add("matchers[%d].name: %q must be a lowercase identifier (letters, digits, '_')", i, m.Name)
		}
		if seen[m.Name] {
			add("matchers[%d].name: duplicate %q", i, m.Name)
		}
		seen[m.Name] = true
		if m.Regex == "" {
			add("matchers[%d].regex: required", i)
		} else if _, err := regexp.Compile(m.Regex); err != nil {
			add("matchers[%d].regex: %v", i, err)
		}
	}
}

func (c *Config) validateHTTP(add func(string, ...any)) {
	if _, _, err := net.SplitHostPort(c.HTTP.Listen); err != nil {
		add("http.listen: %q must be host:port: %v", c.HTTP.Listen, err)
	}
	if c.HTTP.MaxBodyBytes < 1024 {
		add("http.max_body_bytes: must be at least 1024")
	}
	for i, a := range c.HTTP.Agents {
		if a.Name == "" || a.TokenSHA256 == "" {
			add("http.agents[%d]: name and token_sha256 are required", i)
		}
		if strings.HasPrefix(a.TokenSHA256, "tgk_") {
			add("http.agents[%d].token_sha256: looks like a raw token; store only its SHA-256 (see `tollgate token new`)", i)
		}
	}
	if t := c.HTTP.TLS; t != nil && (t.CertFile == "" || t.KeyFile == "") {
		add("http.tls: cert_file and key_file are both required")
	}
}

func (c *Config) validateAgent() error {
	if c.Agent.Name == "" {
		return nil // may come from --agent / TOLLGATE_AGENT; checked at startup
	}
	if !regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`).MatchString(c.Agent.Name) {
		return fmt.Errorf("agent.name: invalid agent name %q", c.Agent.Name)
	}
	return nil
}
