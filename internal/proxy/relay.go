// Package proxy relays MCP JSON-RPC messages between a downstream client and
// an upstream MCP server.
//
// The relay works at the JSON-RPC message level rather than by re-implementing
// an MCP server: every request, response, and notification is forwarded as-is,
// so capabilities Tollgate does not know about (resources, prompts, sampling,
// elicitation, future methods) keep working. Later milestones intercept
// selected methods (for example tools/call) before they reach the upstream.
package proxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// ErrUpstreamClosed is returned by Run when the upstream server closed its side
// of the connection while the client was still connected.
var ErrUpstreamClosed = errors.New("upstream MCP server closed the connection")

// Relay forwards messages between Client (the MCP client that connected to
// Tollgate) and Upstream (the real MCP server).
type Relay struct {
	Client   mcp.Connection
	Upstream mcp.Connection

	// CloseUpstreamInput, if set, half-closes the upstream when the client
	// disconnects (for stdio: closes the child's stdin). The relay then keeps
	// forwarding upstream messages to the client for up to DrainTimeout so
	// responses already in flight are not lost.
	CloseUpstreamInput func() error
	DrainTimeout       time.Duration

	// Interceptor, if set, inspects and may answer or rewrite messages.
	// Nil means plain pass-through.
	Interceptor Interceptor

	inflight sync.WaitGroup

	Logger *slog.Logger
}

// direction labels a pump for logs and error messages.
type direction string

const (
	clientToUpstream direction = "client->upstream"
	upstreamToClient direction = "upstream->client"
)

// pumpResult reports why a pump stopped.
type pumpResult struct {
	dir direction
	err error
}

// Run relays messages until either side closes or ctx is cancelled. Both
// connections are closed before Run returns.
//
// A clean client disconnect (EOF) returns nil. An upstream disconnect returns
// ErrUpstreamClosed. Context cancellation returns the context's error.
func (r *Relay) Run(parent context.Context) error {
	if r.Client == nil || r.Upstream == nil {
		return errors.New("proxy: relay needs both a client and an upstream connection")
	}
	ctx, cancel := context.WithCancel(parent)
	defer cancel()

	results := make(chan pumpResult, 2)
	go func() { results <- r.pump(ctx, clientToUpstream, r.Client, r.Upstream) }()
	go func() { results <- r.pump(ctx, upstreamToClient, r.Upstream, r.Client) }()
	defer func() {
		r.inflight.Wait()
		if r.Interceptor != nil {
			r.Interceptor.Close()
		}
	}()

	first := <-results
	drained := r.drainAfterClientEOF(ctx, first, results)
	cancel()
	r.closeBoth()
	if !drained {
		<-results // wait for the other pump so no goroutine outlives Run
	}
	if parent.Err() != nil {
		return parent.Err()
	}
	return classify(first)
}

// drainAfterClientEOF handles a clean client disconnect when the upstream
// supports half-close: it closes the upstream's input and waits for the
// upstream to finish sending. It reports whether the second pump finished.
func (r *Relay) drainAfterClientEOF(ctx context.Context, first pumpResult, results <-chan pumpResult) bool {
	if first.dir != clientToUpstream || !errors.Is(first.err, io.EOF) || r.CloseUpstreamInput == nil {
		return false
	}
	if err := r.CloseUpstreamInput(); err != nil {
		r.logger().Debug("half-closing upstream", "err", err)
	}
	timeout := r.DrainTimeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-results:
		return true
	case <-timer.C:
		r.logger().Warn("upstream did not finish after client disconnect; closing", "waited", timeout)
	case <-ctx.Done():
	}
	return false
}

// pump copies messages from src to dst until a read or write fails.
func (r *Relay) pump(ctx context.Context, dir direction, src, dst mcp.Connection) pumpResult {
	for {
		msg, err := src.Read(ctx)
		if err != nil {
			return pumpResult{dir: dir, err: err}
		}
		r.logMessage(dir, msg)
		if err := r.route(ctx, dir, msg); err != nil {
			return pumpResult{dir: dir, err: err}
		}
	}
}

// route delivers one message, through the interceptor if there is one.
// Messages that may block (a tools/call waiting for human approval) are
// handled on their own goroutine so other traffic keeps flowing.
func (r *Relay) route(ctx context.Context, dir direction, msg jsonrpc.Message) error {
	ic := r.Interceptor
	switch {
	case ic == nil && dir == clientToUpstream:
		return r.write(ctx, r.Upstream, dir, msg)
	case ic == nil:
		return r.write(ctx, r.Client, dir, msg)
	case dir == upstreamToClient:
		if out := ic.FromUpstream(ctx, msg); out != nil {
			return r.write(ctx, r.Client, dir, out)
		}
		return nil
	case ic.Blocking(msg):
		r.inflight.Add(1)
		go func() {
			defer r.inflight.Done()
			if err := r.dispatchClient(ctx, msg); err != nil {
				r.logger().Debug("dropping message after write failure", "err", err)
			}
		}()
		return nil
	default:
		return r.dispatchClient(ctx, msg)
	}
}

func (r *Relay) dispatchClient(ctx context.Context, msg jsonrpc.Message) error {
	up, down := r.Interceptor.FromClient(ctx, msg)
	if up != nil {
		if err := r.write(ctx, r.Upstream, clientToUpstream, up); err != nil {
			return err
		}
	}
	if down != nil {
		return r.write(ctx, r.Client, upstreamToClient, down)
	}
	return nil
}

func (r *Relay) write(ctx context.Context, dst mcp.Connection, dir direction, msg jsonrpc.Message) error {
	if err := dst.Write(ctx, msg); err != nil {
		return fmt.Errorf("write %s: %w", dir, err)
	}
	return nil
}

// closeBoth closes both connections concurrently. Closing the upstream of a
// command transport waits for the child process to exit, so it must not block
// closing the client.
func (r *Relay) closeBoth() {
	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i, c := range []mcp.Connection{r.Client, r.Upstream} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs[i] = c.Close()
		}()
	}
	wg.Wait()
	// The upstream close error (for example "signal: terminated" from a child
	// that ignored stdin EOF) is informational once the session is over.
	if errs[1] != nil {
		r.logger().Debug("closing upstream", "err", errs[1])
	}
}

// classify turns the first pump result into Run's return value.
func classify(res pumpResult) error {
	eof := errors.Is(res.err, io.EOF)
	switch {
	case res.dir == clientToUpstream && eof:
		return nil
	case res.dir == upstreamToClient && eof:
		return ErrUpstreamClosed
	default:
		return fmt.Errorf("proxy %s: %w", res.dir, res.err)
	}
}

func (r *Relay) logMessage(dir direction, msg jsonrpc.Message) {
	l := r.logger()
	if !l.Enabled(context.Background(), slog.LevelDebug) {
		return
	}
	switch m := msg.(type) {
	case *jsonrpc.Request:
		l.Debug("relay", "dir", dir, "kind", requestKind(m), "method", m.Method, "id", m.ID.Raw())
	case *jsonrpc.Response:
		l.Debug("relay", "dir", dir, "kind", "response", "id", m.ID.Raw(), "error", m.Error != nil)
	}
}

func requestKind(r *jsonrpc.Request) string {
	if r.ID.IsValid() {
		return "request"
	}
	return "notification"
}

func (r *Relay) logger() *slog.Logger {
	if r.Logger != nil {
		return r.Logger
	}
	return slog.New(slog.DiscardHandler)
}
