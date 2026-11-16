package proxy

import (
	"context"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
)

// Interceptor inspects traffic between client and upstream. gate.Session is
// the production implementation.
type Interceptor interface {
	// FromClient handles a client message. It returns what to forward
	// upstream and/or what to answer the client directly (either may be nil).
	FromClient(ctx context.Context, msg jsonrpc.Message) (toUpstream, toClient jsonrpc.Message)
	// FromUpstream handles an upstream message and returns what to send to
	// the client (nil drops it).
	FromUpstream(ctx context.Context, msg jsonrpc.Message) jsonrpc.Message
	// Blocking reports whether FromClient may block on msg.
	Blocking(msg jsonrpc.Message) bool
	// Close releases per-connection state.
	Close()
}

// idKey turns a JSON-RPC id into a map key that keeps 1 and "1" distinct.
func idKey(id jsonrpc.ID) string {
	return fmt.Sprintf("%T:%v", id.Raw(), id.Raw())
}
