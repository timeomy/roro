// Package tests holds end-to-end tests that run the real tollgate binary.
package tests

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// bins holds paths to freshly built tollgate and echo-server executables,
// built once in TestMain.
var bins struct {
	tollgate string
	echo     string
}

func TestMain(m *testing.M) {
	os.Exit(runWithBinaries(m))
}

func runWithBinaries(m *testing.M) int {
	dir, err := os.MkdirTemp("", "tollgate-e2e-")
	if err != nil {
		fmt.Fprintln(os.Stderr, "tempdir:", err)
		return 1
	}
	defer os.RemoveAll(dir)
	exe := ""
	if runtime.GOOS == "windows" {
		exe = ".exe"
	}
	bins.tollgate = filepath.Join(dir, "tollgate"+exe)
	bins.echo = filepath.Join(dir, "echo-server"+exe)
	for out, pkg := range map[string]string{bins.tollgate: "../cmd/tollgate", bins.echo: "../examples/echo-server"} {
		cmd := exec.Command("go", "build", "-o", out, pkg)
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
		if msg, err := cmd.CombinedOutput(); err != nil {
			fmt.Fprintf(os.Stderr, "go build %s: %v\n%s", pkg, err, msg)
			return 1
		}
	}
	return m.Run()
}

func connect(t *testing.T, name string, args ...string) *mcp.ClientSession {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	t.Cleanup(cancel)
	cmd := exec.Command(name, args...)
	cmd.Stderr = testWriter{t}
	client := mcp.NewClient(&mcp.Implementation{Name: "passthrough-test", Version: "test"}, nil)
	session, err := client.Connect(ctx, &mcp.CommandTransport{Command: cmd}, nil)
	if err != nil {
		t.Fatalf("connect %s: %v", name, err)
	}
	t.Cleanup(func() { _ = session.Close() })
	return session
}

// TestPassThroughMatchesDirect runs the same MCP calls directly against the
// echo server and through `tollgate wrap`, and requires identical results.
func TestPassThroughMatchesDirect(t *testing.T) {
	direct := connect(t, bins.echo)
	proxied := connect(t, bins.tollgate, "wrap", "--", bins.echo)

	if diff := jsonDiff(t, direct.InitializeResult(), proxied.InitializeResult()); diff != "" {
		t.Errorf("initialize result differs through proxy (-direct +proxied):\n%s", diff)
	}

	calls := []struct {
		name   string
		params *mcp.CallToolParams
	}{
		{"echo", &mcp.CallToolParams{Name: "echo", Arguments: map[string]any{"text": "hello, 世界 \"quoted\" \n newline"}}},
		{"tool error", &mcp.CallToolParams{Name: "fail", Arguments: map[string]any{"reason": "boom"}}},
	}
	ctx := t.Context()
	for _, c := range calls {
		t.Run(c.name, func(t *testing.T) {
			want, err := direct.CallTool(ctx, c.params)
			if err != nil {
				t.Fatalf("direct CallTool: %v", err)
			}
			got, err := proxied.CallTool(ctx, c.params)
			if err != nil {
				t.Fatalf("proxied CallTool: %v", err)
			}
			if diff := jsonDiff(t, want, got); diff != "" {
				t.Errorf("result differs through proxy (-direct +proxied):\n%s", diff)
			}
		})
	}

	t.Run("tools/list", func(t *testing.T) {
		want, err := direct.ListTools(ctx, nil)
		if err != nil {
			t.Fatalf("direct ListTools: %v", err)
		}
		got, err := proxied.ListTools(ctx, nil)
		if err != nil {
			t.Fatalf("proxied ListTools: %v", err)
		}
		if diff := jsonDiff(t, want, got); diff != "" {
			t.Errorf("tools/list differs through proxy (-direct +proxied):\n%s", diff)
		}
	})

	t.Run("unknown tool error", func(t *testing.T) {
		_, wantErr := direct.CallTool(ctx, &mcp.CallToolParams{Name: "nope"})
		_, gotErr := proxied.CallTool(ctx, &mcp.CallToolParams{Name: "nope"})
		if wantErr == nil || gotErr == nil {
			t.Fatalf("expected errors, got direct=%v proxied=%v", wantErr, gotErr)
		}
		if wantErr.Error() != gotErr.Error() {
			t.Errorf("error differs: direct=%q proxied=%q", wantErr, gotErr)
		}
	})
}

// TestWrapExitsWhenUpstreamFails checks that Tollgate does not keep a client
// hanging when the upstream command cannot run.
func TestWrapExitsWhenUpstreamFails(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bins.tollgate, "wrap", "--", filepath.Join(t.TempDir(), "does-not-exist"))
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("wrap with missing upstream succeeded; output:\n%s", out)
	}
	if ctx.Err() != nil {
		t.Fatal("wrap hung instead of exiting")
	}
}

// TestWrapRequiresDash checks the CLI refuses a command without "--".
func TestWrapRequiresDash(t *testing.T) {
	out, err := exec.Command(bins.tollgate, "wrap", bins.echo).CombinedOutput()
	if err == nil {
		t.Fatalf("wrap without -- succeeded; output:\n%s", out)
	}
}

type testWriter struct{ t *testing.T }

func (w testWriter) Write(p []byte) (int, error) {
	w.t.Logf("stderr: %s", p)
	return len(p), nil
}

// jsonDiff compares two values by their JSON encoding, which is what an MCP
// client actually observes on the wire.
func jsonDiff(t *testing.T, want, got any) string {
	t.Helper()
	w, err := json.Marshal(want)
	if err != nil {
		t.Fatalf("marshal want: %v", err)
	}
	g, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("marshal got: %v", err)
	}
	var wv, gv any
	if err := json.Unmarshal(w, &wv); err != nil {
		t.Fatalf("unmarshal want: %v", err)
	}
	if err := json.Unmarshal(g, &gv); err != nil {
		t.Fatalf("unmarshal got: %v", err)
	}
	return cmp.Diff(wv, gv)
}
