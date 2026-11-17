// Package tests holds end-to-end tests that run the real roro binary
// against real MCP servers over stdio and HTTP.
package tests

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// bins holds paths to binaries built once in TestMain.
var bins struct {
	roro, echo, exfil string
}

func TestMain(m *testing.M) {
	os.Exit(runWithBinaries(m))
}

func runWithBinaries(m *testing.M) int {
	dir, err := os.MkdirTemp("", "roro-e2e-")
	if err != nil {
		fmt.Fprintln(os.Stderr, "tempdir:", err)
		return 1
	}
	defer os.RemoveAll(dir)
	exe := ""
	if runtime.GOOS == "windows" {
		exe = ".exe"
	}
	bins.roro = filepath.Join(dir, "roro"+exe)
	bins.echo = filepath.Join(dir, "echo-server"+exe)
	bins.exfil = filepath.Join(dir, "demo-exfil-server"+exe)
	for out, pkg := range map[string]string{
		bins.roro:  "../cmd/roro",
		bins.echo:  "../examples/echo-server",
		bins.exfil: "../examples/demo-exfil-server",
	} {
		cmd := exec.Command("go", "build", "-o", out, pkg)
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
		if msg, err := cmd.CombinedOutput(); err != nil {
			fmt.Fprintf(os.Stderr, "go build %s: %v\n%s", pkg, err, msg)
			return 1
		}
	}
	return m.Run()
}

// workspace is a directory initialised with `roro init`.
type workspace struct {
	t       *testing.T
	dir     string
	config  string
	sandbox string
	exfil   string // $DEMO_EXFIL_LOG
}

func newWorkspace(t *testing.T, edits ...func(string) string) *workspace {
	t.Helper()
	dir := t.TempDir()
	if resolved, err := filepath.EvalSymlinks(dir); err == nil {
		dir = resolved // macOS: /var -> /private/var, keep paths canonical
	}
	w := &workspace{t: t, dir: dir, config: filepath.Join(dir, "roro.yaml"),
		sandbox: filepath.Join(dir, "sandbox"), exfil: filepath.Join(dir, "exfil.log")}
	w.roro("init", "--dir", dir, "--agent", "test-agent")
	cfg, err := os.ReadFile(w.config)
	if err != nil {
		t.Fatal(err)
	}
	s := strings.Replace(string(cfg), "timeout: 2m", "timeout: 2s", 1)
	for _, e := range edits {
		s = e(s)
	}
	if err := os.WriteFile(w.config, []byte(s), 0o644); err != nil {
		t.Fatal(err)
	}
	return w
}

// roro runs a CLI command and fails the test if it exits non-zero.
func (w *workspace) roro(args ...string) string {
	w.t.Helper()
	out, err := w.roroErr(args...)
	if err != nil {
		w.t.Fatalf("roro %v: %v\n%s", args, err, out)
	}
	return out
}

func (w *workspace) roroErr(args ...string) (string, error) {
	full := args
	if len(args) == 0 || args[0] != "init" {
		full = append([]string{"--config", w.config}, args...)
	}
	cmd := exec.Command(bins.roro, full...)
	var buf bytes.Buffer
	cmd.Stdout, cmd.Stderr = &buf, &buf
	err := cmd.Run()
	return buf.String(), err
}

// connect starts `roro wrap` around server and returns a client session.
func (w *workspace) connect(server string, env ...string) *mcp.ClientSession {
	w.t.Helper()
	args := []string{"--config", w.config, "wrap", "--agent", "test-agent", "--", server}
	return connectCmd(w.t, append(env, "DEMO_EXFIL_LOG="+w.exfil), bins.roro, args...)
}

func connectCmd(t *testing.T, env []string, name string, args ...string) *mcp.ClientSession {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	t.Cleanup(cancel)
	cmd := exec.Command(name, args...)
	cmd.Env = append(os.Environ(), env...)
	cmd.Stderr = testWriter{t}
	client := mcp.NewClient(&mcp.Implementation{Name: "e2e-test", Version: "test"}, nil)
	session, err := client.Connect(ctx, &mcp.CommandTransport{Command: cmd}, nil)
	if err != nil {
		t.Fatalf("connect %s: %v", name, err)
	}
	t.Cleanup(func() { _ = session.Close() })
	return session
}

// decision extracts Roro's decision metadata from a blocked result.
func decision(t *testing.T, res *mcp.CallToolResult) map[string]any {
	t.Helper()
	if res == nil || !res.IsError {
		return nil
	}
	m, _ := res.Meta["im.roro/decision"].(map[string]any)
	return m
}

func call(t *testing.T, s *mcp.ClientSession, tool string, args map[string]any) *mcp.CallToolResult {
	t.Helper()
	res, err := s.CallTool(t.Context(), &mcp.CallToolParams{Name: tool, Arguments: args})
	if err != nil {
		t.Fatalf("CallTool %s: %v", tool, err)
	}
	return res
}

func requireBlocked(t *testing.T, res *mcp.CallToolResult, reason string) {
	t.Helper()
	d := decision(t, res)
	if d == nil || d["decision"] != "deny" || d["reason"] != reason {
		t.Fatalf("expected deny/%s, got isError=%v meta=%v", reason, res.IsError, res.Meta)
	}
}

func requireAllowed(t *testing.T, res *mcp.CallToolResult) {
	t.Helper()
	if d := decision(t, res); d != nil {
		t.Fatalf("expected allowed call, got %v", d)
	}
}

// jsonDiff compares two values by their JSON encoding, which is what an MCP
// client actually observes on the wire.
func jsonDiff(t *testing.T, want, got any) string {
	t.Helper()
	norm := func(v any) any {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		var out any
		if err := json.Unmarshal(b, &out); err != nil {
			t.Fatal(err)
		}
		return out
	}
	return cmp.Diff(norm(want), norm(got))
}

type testWriter struct{ t *testing.T }

func (w testWriter) Write(p []byte) (int, error) {
	w.t.Logf("stderr: %s", bytes.TrimRight(p, "\n"))
	return len(p), nil
}
