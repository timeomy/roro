package app

import (
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/timeomy/roro/internal/audit"
	"github.com/timeomy/roro/internal/config"
	"github.com/timeomy/roro/policies"
)

func TestServerName(t *testing.T) {
	cases := []struct {
		cfgName string
		cmd     []string
		want    string
		wantErr bool
	}{
		{"", []string{"/usr/local/bin/my-server"}, "my-server", false},
		{"", []string{"./bin/srv.exe"}, "srv", false},
		{"", []string{"npx", "-y", "pkg"}, "npx", false},
		{"fs", []string{"npx"}, "fs", false},
		{"fs", nil, "fs", false},
		{"", nil, "", true},
		{"", []string{"..."}, "", true},
	}
	for _, c := range cases {
		cfg := &config.Config{Upstream: config.UpstreamConfig{Name: c.cfgName}}
		got, err := ServerName(cfg, c.cmd)
		if (err != nil) != c.wantErr {
			t.Errorf("ServerName(%q, %v) error = %v", c.cfgName, c.cmd, err)
			continue
		}
		if !c.wantErr && got != c.want {
			t.Errorf("ServerName(%q, %v) = %q, want %q", c.cfgName, c.cmd, got, c.want)
		}
	}
}

func TestOpenBuildsRuntimeAndFailsClosed(t *testing.T) {
	dir := t.TempDir()
	pol := filepath.Join(dir, "p.cedar")
	if err := os.WriteFile(pol, []byte(policies.Starter), 0o600); err != nil {
		t.Fatal(err)
	}
	doc := "version: 1\nstate_dir: st\npolicy: {files: [p.cedar]}\nmatchers: [{name: aws_access_key, regex: AKIA}]\n"
	cfg, err := config.Parse([]byte(doc), dir)
	if err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.DiscardHandler)

	// No signing key yet: Open must refuse.
	if _, err := Open(t.Context(), cfg, logger, "test"); err == nil {
		t.Fatal("Open succeeded without a signing key")
	}
	if _, err := audit.GenerateKey(cfg.Audit.SigningKey); err != nil {
		t.Fatal(err)
	}
	rt, err := Open(t.Context(), cfg, logger, "test")
	if err != nil {
		t.Fatal(err)
	}
	deps := rt.Deps()
	if deps.Mode != config.ModeEnforce || deps.ApprovalTimeout <= 0 || len(deps.Matchers) != 1 {
		t.Fatalf("deps = %+v", deps)
	}
	if err := rt.Close(); err != nil {
		t.Fatal(err)
	}

	// A policy that no longer parses: Open must refuse.
	if err := os.WriteFile(pol, []byte("permit ("), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(t.Context(), cfg, logger, "test"); err == nil {
		t.Fatal("Open succeeded with a broken policy")
	}
}
