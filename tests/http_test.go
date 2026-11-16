package tests

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os/exec"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type bearerTransport struct{ token string }

func (b bearerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+b.token)
	return http.DefaultTransport.RoundTrip(r)
}

var tokenLine = regexp.MustCompile(`(?m)^\s+(tgk_\S+)$`)
var digestLine = regexp.MustCompile(`token_sha256: ([0-9a-f]{64})`)

func freePort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().String()
}

func TestStreamableHTTPServe(t *testing.T) {
	probe := newWorkspace(t)
	out := probe.tollgate("token", "new", "--agent", "http-bot")
	token, digest := tokenLine.FindStringSubmatch(out), digestLine.FindStringSubmatch(out)
	if token == nil || digest == nil {
		t.Fatalf("token output:\n%s", out)
	}
	addr := freePort(t)
	w := newWorkspace(t, func(s string) string {
		return strings.Replace(s, "  listen: 127.0.0.1:8787\n",
			fmt.Sprintf("  listen: %s\n  agents:\n    - name: http-bot\n      token_sha256: %s\n", addr, digest[1]), 1)
	})

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	srv := exec.CommandContext(ctx, bins.tollgate, "--config", w.config, "serve", "--", bins.exfil)
	srv.Env = append(srv.Environ(), "DEMO_EXFIL_LOG="+w.exfil)
	stderr, _ := srv.StderrPipe()
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cancel(); _ = srv.Wait() })
	waitForLine(t, stderr, "serving MCP over HTTP")
	url := "http://" + addr + "/mcp"

	// No token: rejected before reaching MCP.
	resp, err := http.Post(url, "application/json", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("no-token status = %d, want 401", resp.StatusCode)
	}

	client := mcp.NewClient(&mcp.Implementation{Name: "http-e2e", Version: "test"}, nil)
	session, err := client.Connect(t.Context(), &mcp.StreamableClientTransport{
		Endpoint: url, HTTPClient: &http.Client{Transport: bearerTransport{token[1]}, Timeout: 30 * time.Second},
		DisableStandaloneSSE: true, MaxRetries: -1,
	}, nil)
	if err != nil {
		t.Fatalf("connect over HTTP: %v", err)
	}
	defer session.Close()

	tools, err := session.ListTools(t.Context(), nil)
	if err != nil || len(tools.Tools) != 3 {
		t.Fatalf("ListTools = %v, %v", tools, err)
	}
	requireBlocked(t, call(t, session, "exfiltrate", map[string]any{"data": fakeKey}), "dangerous_tool_blocked")
	res := call(t, session, "http_post", map[string]any{"url": "https://api.github.com/x", "body": "ok"})
	requireAllowed(t, res)

	logs := w.tollgate("logs", "--agent", "http-bot")
	if !strings.Contains(logs, "dangerous_tool_blocked") || !strings.Contains(logs, "http_post") {
		t.Fatalf("logs:\n%s", logs)
	}
}

func waitForLine(t *testing.T, r io.Reader, want string) {
	t.Helper()
	found := make(chan bool, 1)
	go func() {
		sc := bufio.NewScanner(r)
		ok := false
		for sc.Scan() {
			t.Log("serve: " + sc.Text())
			if !ok && strings.Contains(sc.Text(), want) {
				ok = true
				found <- true
			}
		}
		if !ok {
			found <- false
		}
	}()
	select {
	case ok := <-found:
		if !ok {
			t.Fatalf("server exited before %q", want)
		}
	case <-time.After(20 * time.Second):
		t.Fatalf("timed out waiting for %q", want)
	}
}
