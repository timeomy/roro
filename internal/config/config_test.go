package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writePolicy(t *testing.T, dir string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "p.cedar"), []byte("permit(principal, action, resource);"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestParseAppliesDefaultsAndResolvesPaths(t *testing.T) {
	dir := t.TempDir()
	writePolicy(t, dir)
	cfg, err := Parse([]byte("version: 1\npolicy:\n  files: [p.cedar]\n"), dir)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.Mode != ModeEnforce || cfg.Pinning.OnChange != PinBlock {
		t.Errorf("defaults not applied: mode=%q pin=%q", cfg.Mode, cfg.Pinning.OnChange)
	}
	if cfg.Approval.Timeout.Duration != 2*time.Minute {
		t.Errorf("approval timeout = %s", cfg.Approval.Timeout)
	}
	if want := filepath.Join(dir, ".tollgate", "audit.db"); cfg.Audit.Path != want {
		t.Errorf("audit path = %q, want %q", cfg.Audit.Path, want)
	}
	if cfg.Policy.Files[0] != filepath.Join(dir, "p.cedar") {
		t.Errorf("policy path not resolved: %q", cfg.Policy.Files[0])
	}
}

func TestParseFailsClosed(t *testing.T) {
	dir := t.TempDir()
	writePolicy(t, dir)
	cases := map[string]string{
		"unknown key":       "version: 1\npolicy: {files: [p.cedar]}\nsurprise: true\n",
		"wrong version":     "version: 2\npolicy: {files: [p.cedar]}\n",
		"bad mode":          "version: 1\nmode: yolo\npolicy: {files: [p.cedar]}\n",
		"no policy":         "version: 1\n",
		"missing policy":    "version: 1\npolicy: {files: [nope.cedar]}\n",
		"bad duration":      "version: 1\npolicy: {files: [p.cedar]}\napproval: {timeout: soon}\n",
		"bad regex":         "version: 1\npolicy: {files: [p.cedar]}\nmatchers: [{name: x, regex: \"(\"}]\n",
		"bad matcher name":  "version: 1\npolicy: {files: [p.cedar]}\nmatchers: [{name: Bad-Name, regex: a}]\n",
		"bad pin action":    "version: 1\npolicy: {files: [p.cedar]}\npinning: {on_change: shrug}\n",
		"raw token":         "version: 1\npolicy: {files: [p.cedar]}\nhttp: {agents: [{name: a, token_sha256: tgk_abc}]}\n",
		"bad agent":         "version: 1\npolicy: {files: [p.cedar]}\nagent: {name: \"Bad Agent\"}\n",
		"two documents":     "version: 1\npolicy: {files: [p.cedar]}\n---\nversion: 1\n",
		"empty":             "",
		"command and url":   "version: 1\npolicy: {files: [p.cedar]}\nupstream: {command: [x], url: \"http://h\"}\n",
		"wrong type":        "version: one\npolicy: {files: [p.cedar]}\n",
		"zero checkpoint":   "version: 1\npolicy: {files: [p.cedar]}\naudit: {checkpoint_every: -1}\n",
		"bad listen":        "version: 1\npolicy: {files: [p.cedar]}\nhttp: {listen: nope}\n",
		"approval too long": "version: 1\npolicy: {files: [p.cedar]}\napproval: {timeout: 48h}\n",
	}
	for name, doc := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse([]byte(doc), dir); err == nil {
				t.Fatalf("Parse accepted invalid config:\n%s", doc)
			}
		})
	}
}

func TestLoadReportsPath(t *testing.T) {
	dir := t.TempDir()
	writePolicy(t, dir)
	p := filepath.Join(dir, "tollgate.yaml")
	if err := os.WriteFile(p, []byte("version: 1\nmode: monitor\npolicy: {files: [p.cedar]}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Path() != p || cfg.Mode != ModeMonitor {
		t.Errorf("path=%q mode=%q", cfg.Path(), cfg.Mode)
	}
	if _, err := Load(filepath.Join(dir, "missing.yaml")); err == nil || !strings.Contains(err.Error(), "missing.yaml") {
		t.Errorf("missing file error = %v", err)
	}
}
