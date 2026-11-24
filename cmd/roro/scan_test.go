package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func runScanCmd(t *testing.T, args ...string) (string, error) {
	t.Helper()
	cmd := newRootCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs(append([]string{"scan"}, args...))
	err := cmd.Execute()
	return out.String(), err
}

func fixture(name string) string { return filepath.Join("..", "..", "testdata", "scan", name) }

func TestScanFailsOnHighFindings(t *testing.T) {
	out, err := runScanCmd(t, "--file", fixture("risky.json"), "--no-color")
	var fe findingsError
	if !errors.As(err, &fe) || fe.n != 5 {
		t.Fatalf("err = %v, want 5 high findings", err)
	}
	if !strings.Contains(out, "Secret written in the config file") || strings.Contains(out, "ghp_") {
		t.Fatalf("output:\n%s", out)
	}
	if !strings.Contains(fe.Error(), "5 findings") {
		t.Fatalf("message = %q", fe.Error())
	}
}

func TestScanFailOnLevels(t *testing.T) {
	if _, err := runScanCmd(t, "--file", fixture("codex.toml")); err != nil {
		t.Fatalf("codex has no high findings, got %v", err)
	}
	if _, err := runScanCmd(t, "--file", fixture("codex.toml"), "--fail-on", "medium"); err == nil {
		t.Fatal("want failure at medium")
	}
	if _, err := runScanCmd(t, "--file", fixture("risky.json"), "--fail-on", "none"); err != nil {
		t.Fatalf("none should never fail: %v", err)
	}
	for _, bad := range [][]string{{"--fail-on", "critical"}, {"--show", "none"}} {
		if _, err := runScanCmd(t, append([]string{"--file", fixture("codex.toml")}, bad...)...); err == nil || !strings.Contains(err.Error(), "invalid") {
			t.Fatalf("%v: err = %v", bad, err)
		}
	}
}

func TestScanJSON(t *testing.T) {
	out, err := runScanCmd(t, "--file", fixture("risky.json"), "--file", fixture("codex.toml"), "--json", "--fail-on", "none")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Version int `json:"version"`
		Summary struct {
			Servers int `json:"servers"`
		} `json:"summary"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil || doc.Version != 1 || doc.Summary.Servers != 7 {
		t.Fatalf("json (%v): %s", err, out)
	}
}

func TestScanMissingFile(t *testing.T) {
	out, err := runScanCmd(t, "--file", filepath.Join(t.TempDir(), "nope.json"))
	if err == nil || !strings.Contains(err.Error(), "1 file could not be read") || !strings.Contains(out, "could not read this file") {
		t.Fatalf("err = %v, out = %s", err, out)
	}
}

func TestScanDefaultLocations(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("APPDATA", filepath.Join(home, "AppData"))
	t.Chdir(t.TempDir())

	out, err := runScanCmd(t)
	if err != nil || !strings.Contains(out, "No MCP configuration found") {
		t.Fatalf("empty home: err = %v, out = %s", err, out)
	}

	cursor := filepath.Join(home, ".cursor", "mcp.json")
	if err := os.MkdirAll(filepath.Dir(cursor), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cursor, []byte(`{"mcpServers":{"fs":{"command":"npx","args":["-y","srv@1.0.0","`+home+`"]}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(".mcp.json", []byte(`{"mcpServers":{"p":{"url":"http://evil.example/mcp"}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err = runScanCmd(t, "--no-color")
	var fe findingsError
	if !errors.As(err, &fe) || fe.n != 1 {
		t.Fatalf("err = %v\n%s", err, out)
	}
	for _, want := range []string{"Cursor", "This project", "Access to a very broad folder", "Remote server over plain HTTP"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q:\n%s", want, out)
		}
	}
}

func TestUseColor(t *testing.T) {
	if useColor(&bytes.Buffer{}, false) {
		t.Fatal("buffer is not a terminal")
	}
	if useColor(os.Stdout, true) {
		t.Fatal("--no-color ignored")
	}
	t.Setenv("NO_COLOR", "1")
	if useColor(os.Stdout, false) {
		t.Fatal("NO_COLOR ignored")
	}
}
