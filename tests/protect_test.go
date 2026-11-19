package tests

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// homeEnv points every "where is my home" lookup at dir.
func homeEnv(dir string) []string {
	return []string{"HOME=" + dir, "USERPROFILE=" + dir, "APPDATA=" + filepath.Join(dir, "AppData", "Roaming"), "RORO_CONFIG="}
}

func roroAt(t *testing.T, home string, args ...string) string {
	t.Helper()
	cmd := exec.Command(bins.roro, args...)
	cmd.Dir = t.TempDir() // not the home directory: commands must find ~/.roro on their own
	cmd.Env = append(os.Environ(), homeEnv(home)...)
	var buf bytes.Buffer
	cmd.Stdout, cmd.Stderr = &buf, &buf
	if err := cmd.Run(); err != nil {
		t.Fatalf("roro %v: %v\n%s", args, err, buf.String())
	}
	return buf.String()
}

type cursorConfig struct {
	Keep       string `json:"keep"`
	MCPServers map[string]struct {
		Command string   `json:"command"`
		Args    []string `json:"args"`
	} `json:"mcpServers"`
}

func readCursor(t *testing.T, path string) cursorConfig {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var c cursorConfig
	if err := json.Unmarshal(data, &c); err != nil {
		t.Fatalf("%v\n%s", err, data)
	}
	return c
}

func TestProtectThenUseThenUnprotect(t *testing.T) {
	home := t.TempDir()
	if resolved, err := filepath.EvalSymlinks(home); err == nil {
		home = resolved
	}
	cfgPath := filepath.Join(home, ".cursor", "mcp.json")
	if err := os.MkdirAll(filepath.Dir(cfgPath), 0o755); err != nil {
		t.Fatal(err)
	}
	original, _ := json.MarshalIndent(map[string]any{
		"keep":       "me",
		"mcpServers": map[string]any{"echo": map[string]any{"command": bins.echo, "args": []string{}}},
	}, "", "  ")
	if err := os.WriteFile(cfgPath, original, 0o600); err != nil {
		t.Fatal(err)
	}

	// A dry run reports the plan and touches nothing.
	out := roroAt(t, home, "protect", "--dry-run")
	if !strings.Contains(out, "Cursor") || !strings.Contains(out, "echo") {
		t.Fatalf("dry run output:\n%s", out)
	}
	if now, _ := os.ReadFile(cfgPath); !bytes.Equal(now, original) {
		t.Fatal("dry run changed the client config")
	}
	if _, err := os.Stat(filepath.Join(home, ".roro")); !os.IsNotExist(err) {
		t.Fatal("dry run created ~/.roro")
	}

	out = roroAt(t, home, "protect", "--yes")
	if !strings.Contains(out, "Restart") {
		t.Errorf("protect did not tell the user to restart:\n%s", out)
	}
	c := readCursor(t, cfgPath)
	entry := c.MCPServers["echo"]
	if c.Keep != "me" || filepath.Base(entry.Command) != filepath.Base(bins.roro) {
		t.Fatalf("config after protect: %+v", c)
	}
	if info, err := os.Stat(cfgPath); err != nil || (info.Mode().Perm() != 0o600 && os.PathSeparator == '/') {
		t.Errorf("file mode changed: %v %v", info.Mode(), err)
	}
	backups, _ := filepath.Glob(cfgPath + ".before-roro*")
	if len(backups) != 1 {
		t.Fatalf("backups = %v", backups)
	}
	if saved, _ := os.ReadFile(backups[0]); !bytes.Equal(saved, original) {
		t.Error("backup differs from the original file")
	}

	// The client now launches the server through Roro, exactly as written.
	s := connectCmd(t, homeEnv(home), entry.Command, entry.Args...)
	requireAllowed(t, call(t, s, "echo", map[string]any{"text": "hello"}))
	requireBlocked(t, call(t, s, "echo", map[string]any{"text": "key AKIAIOSFODNN7EXAMPLE"}), "secret_in_arguments")
	requireBlocked(t, call(t, s, "echo", map[string]any{"text": "ghp_abcdefghijklmnopqrstuvwxyzABCDEFGHIJ"}), "secret_in_arguments")
	_ = s.Close()

	// Everyday commands work from any directory with no flags.
	logs := roroAt(t, home, "logs")
	if !strings.Contains(logs, "cursor") || !strings.Contains(logs, "secret_in_arguments") || !strings.Contains(logs, "echo") {
		t.Errorf("logs:\n%s", logs)
	}
	if v := roroAt(t, home, "verify"); !strings.Contains(v, "OK") {
		t.Errorf("verify:\n%s", v)
	}

	// Running protect again is harmless.
	again := roroAt(t, home, "protect", "--yes")
	if !strings.Contains(again, "already protected") {
		t.Errorf("second protect:\n%s", again)
	}
	if more, _ := filepath.Glob(cfgPath + ".before-roro*"); len(more) != 1 {
		t.Errorf("second protect made another backup: %v", more)
	}

	roroAt(t, home, "unprotect", "--yes")
	c = readCursor(t, cfgPath)
	if c.MCPServers["echo"].Command != bins.echo || len(c.MCPServers["echo"].Args) != 0 || c.Keep != "me" {
		t.Fatalf("config after unprotect: %+v", c)
	}
}

func TestProtectWithNothingInstalled(t *testing.T) {
	out := roroAt(t, t.TempDir(), "protect", "--yes")
	if !strings.Contains(out, "No MCP servers found") {
		t.Errorf("output:\n%s", out)
	}
}
