package proxy

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// TestRunStdioWithRealProcess runs RunStdio against the echo example server
// over in-process pipes standing in for Tollgate's stdin/stdout.
func TestRunStdioWithRealProcess(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "echo-server")
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}
	if out, err := exec.Command("go", "build", "-o", bin, "../../examples/echo-server").CombinedOutput(); err != nil {
		t.Fatalf("build echo-server: %v\n%s", err, out)
	}
	clientR, proxyW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	proxyR, clientW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		done <- RunStdio(t.Context(), StdioOptions{
			Command: bin, ClientIn: proxyR, ClientOut: proxyW, TerminateGrace: time.Second,
		})
	}()
	client := mcp.NewClient(&mcp.Implementation{Name: "t", Version: "0"}, nil)
	sess, err := client.Connect(t.Context(), &mcp.IOTransport{Reader: clientR, Writer: clientW}, nil)
	if err != nil {
		t.Fatal(err)
	}
	res, err := sess.CallTool(t.Context(), &mcp.CallToolParams{Name: "echo", Arguments: map[string]any{"text": "x"}})
	if err != nil || res.IsError {
		t.Fatalf("CallTool = %+v, %v", res, err)
	}
	_ = sess.Close()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("RunStdio = %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("RunStdio did not return after client disconnect")
	}
	if err := RunStdio(context.Background(), StdioOptions{}); err == nil {
		t.Fatal("RunStdio without a command succeeded")
	}
}
