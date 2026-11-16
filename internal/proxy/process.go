package proxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"syscall"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// upstreamProcess is a child MCP server reached over its stdin/stdout.
//
// Tollgate manages the process itself instead of using mcp.CommandTransport
// so it can half-close: when the client disconnects, Tollgate closes the
// child's stdin but keeps reading its stdout, so responses already in flight
// still reach the client before shutdown.
type upstreamProcess struct {
	cmd   *exec.Cmd
	stdin io.WriteCloser
	conn  mcp.Connection
	grace time.Duration
}

func startUpstream(ctx context.Context, name string, args []string, stderr io.Writer, grace time.Duration) (*upstreamProcess, error) {
	// exec.Command, not CommandContext: shutdown goes through stop(), which
	// closes stdin first and only then signals, as the MCP stdio spec asks.
	cmd := exec.Command(name, args...)
	cmd.Stderr = stderr
	if cmd.Stderr == nil {
		cmd.Stderr = os.Stderr
	}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("proxy: upstream stdin: %w", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("proxy: upstream stdout: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("proxy: start upstream %q: %w", name, err)
	}
	conn, err := (&mcp.IOTransport{Reader: stdout, Writer: stdin}).Connect(ctx)
	if err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return nil, fmt.Errorf("proxy: open upstream stream: %w", err)
	}
	if grace <= 0 {
		grace = DefaultTerminateGrace
	}
	return &upstreamProcess{cmd: cmd, stdin: stdin, conn: conn, grace: grace}, nil
}

// closeInput closes the child's stdin, the MCP stdio signal to shut down.
func (p *upstreamProcess) closeInput() error {
	err := p.stdin.Close()
	if errors.Is(err, os.ErrClosed) {
		return nil
	}
	return err
}

// stop closes stdin, waits up to the grace period for the child to exit, then
// sends SIGTERM, waits again, and finally kills it. It returns the child's
// exit error, if any.
func (p *upstreamProcess) stop() error {
	_ = p.closeInput()
	done := make(chan error, 1)
	go func() { done <- p.cmd.Wait() }()

	select {
	case err := <-done:
		return err
	case <-time.After(p.grace):
	}
	// On Windows SIGTERM is not deliverable; Signal fails and we kill.
	if err := p.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		_ = p.cmd.Process.Kill()
		return <-done
	}
	select {
	case err := <-done:
		return err
	case <-time.After(p.grace):
		_ = p.cmd.Process.Kill()
		return <-done
	}
}
