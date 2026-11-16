package proxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// DefaultTerminateGrace is how long Tollgate waits after closing the
// upstream's stdin before signalling it to stop, and again before killing it.
// It also bounds how long in-flight upstream responses are drained after the
// client disconnects.
const DefaultTerminateGrace = 5 * time.Second

// StdioOptions configures a stdio-to-stdio proxy session.
type StdioOptions struct {
	// Command is the upstream MCP server executable; Args are its arguments.
	Command string
	Args    []string

	// ClientIn and ClientOut carry the downstream MCP client's traffic.
	// Defaults: os.Stdin and os.Stdout.
	ClientIn  io.ReadCloser
	ClientOut io.WriteCloser

	// UpstreamStderr receives the upstream server's stderr. Default: os.Stderr,
	// so MCP hosts that capture server logs (Claude Desktop, Cursor) still see
	// them. Tollgate never writes upstream stderr to stdout.
	UpstreamStderr io.Writer

	// TerminateGrace overrides DefaultTerminateGrace when positive.
	TerminateGrace time.Duration

	// Interceptor enforces policy; nil means plain pass-through.
	Interceptor Interceptor

	Logger *slog.Logger
}

// RunStdio starts the upstream command and relays MCP traffic between the
// client streams and the upstream process until one side closes.
func RunStdio(ctx context.Context, opts StdioOptions) error {
	if opts.Command == "" {
		return errors.New("proxy: no upstream command given")
	}
	grace := opts.TerminateGrace
	if grace <= 0 {
		grace = DefaultTerminateGrace
	}
	up, err := startUpstream(ctx, opts.Command, opts.Args, opts.UpstreamStderr, grace)
	if err != nil {
		return err
	}
	client, err := (&mcp.IOTransport{
		Reader: orDefault[io.ReadCloser](opts.ClientIn, os.Stdin),
		Writer: orDefault[io.WriteCloser](opts.ClientOut, os.Stdout),
	}).Connect(ctx)
	if err != nil {
		_ = up.stop()
		return fmt.Errorf("proxy: open client stream: %w", err)
	}

	relay := &Relay{
		Client:             client,
		Upstream:           up.conn,
		CloseUpstreamInput: up.closeInput,
		DrainTimeout:       grace,
		Interceptor:        opts.Interceptor,
		Logger:             opts.Logger,
	}
	runErr := relay.Run(ctx)
	if exitErr := up.stop(); exitErr != nil && opts.Logger != nil {
		opts.Logger.Debug("upstream exit", "err", exitErr)
	}
	return runErr
}

func orDefault[T comparable](v, def T) T {
	var zero T
	if v == zero {
		return def
	}
	return v
}
