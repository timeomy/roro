package tests

import (
	"context"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// TestPassThroughMatchesDirect runs the same MCP calls directly against the
// echo server and through `tollgate wrap` with the starter policy, and
// requires identical results for allowed calls.
func TestPassThroughMatchesDirect(t *testing.T) {
	w := newWorkspace(t)
	direct := connectCmd(t, nil, bins.echo)
	proxied := w.connect(bins.echo)

	if diff := jsonDiff(t, direct.InitializeResult(), proxied.InitializeResult()); diff != "" {
		t.Errorf("initialize result differs through proxy (-direct +proxied):\n%s", diff)
	}
	ctx := t.Context()
	t.Run("tools/list", func(t *testing.T) {
		want, err := direct.ListTools(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		got, err := proxied.ListTools(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		if diff := jsonDiff(t, want, got); diff != "" {
			t.Errorf("tools/list differs (-direct +proxied):\n%s", diff)
		}
	})
	for name, params := range map[string]*mcp.CallToolParams{
		"echo":       {Name: "echo", Arguments: map[string]any{"text": "hello, 世界 \"quoted\" \n newline"}},
		"tool error": {Name: "fail", Arguments: map[string]any{"reason": "boom"}},
	} {
		t.Run(name, func(t *testing.T) {
			want, err := direct.CallTool(ctx, params)
			if err != nil {
				t.Fatal(err)
			}
			got, err := proxied.CallTool(ctx, params)
			if err != nil {
				t.Fatal(err)
			}
			if diff := jsonDiff(t, want, got); diff != "" {
				t.Errorf("result differs (-direct +proxied):\n%s", diff)
			}
		})
	}
	t.Run("unlisted tool denied by policy", func(t *testing.T) {
		requireBlocked(t, call(t, proxied, "nope", nil), "no_matching_permit")
	})
}

func TestWrapFailsClosed(t *testing.T) {
	w := newWorkspace(t)
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	cases := map[string][]string{
		"missing upstream": {"--config", w.config, "wrap", "--", filepath.Join(t.TempDir(), "missing")},
		"no dash":          {"--config", w.config, "wrap", bins.echo},
		"missing config":   {"--config", filepath.Join(t.TempDir(), "none.yaml"), "wrap", "--", bins.echo},
		"bad agent":        {"--config", w.config, "wrap", "--agent", "Bad Name", "--", bins.echo},
	}
	for name, args := range cases {
		t.Run(name, func(t *testing.T) {
			out, err := exec.CommandContext(ctx, bins.tollgate, args...).CombinedOutput()
			if err == nil {
				t.Fatalf("wrap succeeded; output:\n%s", out)
			}
			if ctx.Err() != nil {
				t.Fatal("wrap hung instead of exiting")
			}
		})
	}
}
