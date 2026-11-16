package proxy

import (
	"bufio"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// TestRelayDeliversResponseAfterClientEOF checks the half-close path: the
// client sends a request and immediately closes its input; the upstream only
// answers after seeing its own input closed. The answer must still reach the
// client.
func TestRelayDeliversResponseAfterClientEOF(t *testing.T) {
	ctx := t.Context()
	clientToRelayR, clientToRelayW := io.Pipe()
	relayToClientR, relayToClientW := io.Pipe()
	relayToUpR, relayToUpW := io.Pipe()
	upToRelayR, upToRelayW := io.Pipe()

	clientConn, _ := (&mcp.IOTransport{Reader: clientToRelayR, Writer: relayToClientW}).Connect(ctx)
	upConn, _ := (&mcp.IOTransport{Reader: upToRelayR, Writer: relayToUpW}).Connect(ctx)

	// Fake upstream: read the request, wait for stdin EOF, then reply.
	go func() {
		sc := bufio.NewScanner(relayToUpR)
		sc.Scan() // the request
		for sc.Scan() {
		}
		_, _ = io.WriteString(upToRelayW, `{"jsonrpc":"2.0","id":7,"result":{"late":true}}`+"\n")
		_ = upToRelayW.Close()
	}()

	relayErr := make(chan error, 1)
	go func() {
		relayErr <- (&Relay{
			Client:             clientConn,
			Upstream:           upConn,
			CloseUpstreamInput: relayToUpW.Close,
			DrainTimeout:       2 * time.Second,
		}).Run(ctx)
	}()

	_, _ = io.WriteString(clientToRelayW, `{"jsonrpc":"2.0","id":7,"method":"ping"}`+"\n")
	_ = clientToRelayW.Close()

	line, err := bufio.NewReader(relayToClientR).ReadString('\n')
	if err != nil {
		t.Fatalf("reading response after client EOF: %v", err)
	}
	if !strings.Contains(line, `"late":true`) || !strings.Contains(line, `"id":7`) {
		t.Fatalf("response = %q, want the late upstream reply", line)
	}
	go func() { _, _ = io.Copy(io.Discard, relayToClientR) }()

	select {
	case err := <-relayErr:
		if err != nil {
			t.Fatalf("relay error = %v, want nil after clean client EOF", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("relay did not stop after draining")
	}
}
