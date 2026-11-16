package proxy

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type echoIn struct {
	Text string `json:"text"`
}

func newEchoServer() *mcp.Server {
	s := mcp.NewServer(&mcp.Implementation{Name: "echo", Version: "test"}, nil)
	mcp.AddTool(s, &mcp.Tool{Name: "echo", Description: "echo text"},
		func(_ context.Context, _ *mcp.CallToolRequest, in echoIn) (*mcp.CallToolResult, echoIn, error) {
			return nil, in, nil
		})
	return s
}

// harness wires client <-> relay <-> server entirely in memory.
type harness struct {
	session  *mcp.ClientSession
	relayErr chan error
	cancel   context.CancelFunc
}

func startHarness(t *testing.T) *harness {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())

	clientT, relayClientT := mcp.NewInMemoryTransports()
	relayUpT, serverT := mcp.NewInMemoryTransports()

	if _, err := newEchoServer().Connect(ctx, serverT, nil); err != nil {
		t.Fatalf("server connect: %v", err)
	}
	clientConn, err := relayClientT.Connect(ctx)
	if err != nil {
		t.Fatalf("relay client side: %v", err)
	}
	upConn, err := relayUpT.Connect(ctx)
	if err != nil {
		t.Fatalf("relay upstream side: %v", err)
	}

	h := &harness{relayErr: make(chan error, 1), cancel: cancel}
	go func() { h.relayErr <- (&Relay{Client: clientConn, Upstream: upConn}).Run(ctx) }()

	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "test"}, nil)
	h.session, err = client.Connect(ctx, clientT, nil)
	if err != nil {
		t.Fatalf("client connect through relay: %v", err)
	}
	t.Cleanup(cancel)
	return h
}

func (h *harness) waitRelay(t *testing.T) error {
	t.Helper()
	select {
	case err := <-h.relayErr:
		return err
	case <-time.After(5 * time.Second):
		t.Fatal("relay did not stop")
		return nil
	}
}

func TestRelayForwardsToolsListAndCall(t *testing.T) {
	h := startHarness(t)
	ctx := t.Context()

	tools, err := h.session.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	if len(tools.Tools) != 1 || tools.Tools[0].Name != "echo" {
		t.Fatalf("tools = %+v, want one tool named echo", tools.Tools)
	}

	res, err := h.session.CallTool(ctx, &mcp.CallToolParams{
		Name:      "echo",
		Arguments: map[string]any{"text": "hello through tollgate"},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	want := map[string]any{"text": "hello through tollgate"}
	if diff := cmp.Diff(want, res.StructuredContent); diff != "" {
		t.Errorf("structured content mismatch (-want +got):\n%s", diff)
	}
	if err := h.session.Ping(ctx, nil); err != nil {
		t.Errorf("Ping through relay: %v", err)
	}
}

func TestRelayCleanClientDisconnectReturnsNil(t *testing.T) {
	h := startHarness(t)
	if err := h.session.Close(); err != nil {
		t.Fatalf("client close: %v", err)
	}
	if err := h.waitRelay(t); err != nil {
		t.Fatalf("relay error after client disconnect = %v, want nil", err)
	}
}

func TestRelayContextCancelStops(t *testing.T) {
	h := startHarness(t)
	h.cancel()
	if err := h.waitRelay(t); !errors.Is(err, context.Canceled) {
		t.Fatalf("relay error after cancel = %v, want context.Canceled", err)
	}
}

func TestRelayRejectsMissingConnection(t *testing.T) {
	if err := (&Relay{}).Run(t.Context()); err == nil {
		t.Fatal("Run with nil connections succeeded, want error")
	}
}
