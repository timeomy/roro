// Package gate is Tollgate's policy enforcement point. A Session sits on one
// client<->upstream connection and inspects the JSON-RPC traffic:
//
//   - tools/call requests run the decision pipeline (kill switch, pinning,
//     rate counters, matchers, Cedar policy, human approval) and are either
//     forwarded or answered with a denial; every decision is audited.
//   - tools/list responses are checked against pinned tool definitions.
//   - everything else passes through unchanged.
package gate

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"

	"github.com/timeomy/tollgate/internal/approval"
	"github.com/timeomy/tollgate/internal/audit"
	"github.com/timeomy/tollgate/internal/config"
	"github.com/timeomy/tollgate/internal/identity"
	"github.com/timeomy/tollgate/internal/killswitch"
	"github.com/timeomy/tollgate/internal/observe"
	"github.com/timeomy/tollgate/internal/pin"
	"github.com/timeomy/tollgate/internal/policy"
)

// KillChecker reports kill switch state.
type KillChecker interface {
	Check(ctx context.Context, agent string) (killswitch.Status, error)
}

// PinStore records and checks tool definitions.
type PinStore interface {
	Observe(ctx context.Context, server string, tools []pin.Tool) ([]pin.Change, error)
	Status(ctx context.Context, server, tool string) (string, error)
}

// Deps are the shared components a Session uses. All fields are required
// except Logger and Now.
type Deps struct {
	Policy          policy.Engine
	Matchers        []policy.Matcher
	Rates           *policy.RateCounter
	Audit           audit.Log
	Kill            KillChecker
	Pins            PinStore
	Approver        approval.Approver
	Telemetry       *observe.Telemetry
	Mode            string // config.ModeEnforce or config.ModeMonitor
	PinOnChange     string // config.PinBlock or config.PinAlert
	ApprovalTimeout time.Duration
	Logger          *slog.Logger
	Now             func() time.Time
}

func (d Deps) validate() error {
	switch {
	case d.Policy == nil, d.Rates == nil, d.Audit == nil, d.Kill == nil, d.Pins == nil,
		d.Approver == nil, d.Telemetry == nil:
		return fmt.Errorf("gate: missing dependency")
	case d.Mode != config.ModeEnforce && d.Mode != config.ModeMonitor:
		return fmt.Errorf("gate: invalid mode %q", d.Mode)
	case d.PinOnChange != config.PinBlock && d.PinOnChange != config.PinAlert:
		return fmt.Errorf("gate: invalid pin action %q", d.PinOnChange)
	case d.ApprovalTimeout <= 0:
		return fmt.Errorf("gate: approval timeout must be positive")
	}
	return nil
}

// SessionInfo identifies who is on the other end of a connection.
type SessionInfo struct {
	Agent     identity.Agent
	Server    string // upstream server name
	Transport string // observe.TransportPipe or observe.TransportTCP
	SessionID string // proxy session id (HTTP mode, or a random id for stdio)
}

// Session enforces policy on one connection. It is safe for concurrent use.
type Session struct {
	deps Deps
	info SessionInfo
	log  *slog.Logger

	mu      sync.Mutex
	lists   map[string]bool               // pending tools/list request ids
	calls   map[string]*pendingCall       // forwarded tools/call request ids
	cancels map[string]context.CancelFunc // approval waits, by request id
	closed  bool
}

// NewSession validates deps and identity and returns a Session. It fails
// closed: a missing component or identity is an error, not a pass-through.
func NewSession(deps Deps, info SessionInfo) (*Session, error) {
	if err := deps.validate(); err != nil {
		return nil, err
	}
	if err := info.Agent.Validate(); err != nil {
		return nil, err
	}
	if info.Server == "" {
		return nil, fmt.Errorf("gate: upstream server name is required")
	}
	if deps.Now == nil {
		deps.Now = time.Now
	}
	l := deps.Logger
	if l == nil {
		l = slog.New(slog.DiscardHandler)
	}
	return &Session{
		deps: deps, info: info,
		log:     l.With("agent", info.Agent.Name, "server", info.Server),
		lists:   map[string]bool{},
		calls:   map[string]*pendingCall{},
		cancels: map[string]context.CancelFunc{},
	}, nil
}

// Blocking reports whether FromClient may block on msg (a human approval).
// Relays run such messages on their own goroutine.
func (s *Session) Blocking(msg jsonrpc.Message) bool {
	r, ok := msg.(*jsonrpc.Request)
	return ok && r.Method == "tools/call"
}

// FromClient handles a message from the client. It returns the message to
// send upstream and/or a message to send back to the client.
func (s *Session) FromClient(ctx context.Context, msg jsonrpc.Message) (toUpstream, toClient jsonrpc.Message) {
	req, ok := msg.(*jsonrpc.Request)
	if !ok {
		return msg, nil // client's response to a server-initiated request
	}
	switch req.Method {
	case "tools/call":
		if !req.ID.IsValid() {
			return nil, nil // a tools/call notification is invalid; drop it
		}
		return s.handleCall(ctx, req)
	case "tools/list":
		if req.ID.IsValid() {
			s.mu.Lock()
			s.lists[idKey(req.ID)] = true
			s.mu.Unlock()
		}
	case "notifications/cancelled":
		s.cancelApproval(req)
	}
	return msg, nil
}

// FromUpstream handles a message from the upstream server and returns what
// to send to the client (nil to drop).
func (s *Session) FromUpstream(ctx context.Context, msg jsonrpc.Message) jsonrpc.Message {
	resp, ok := msg.(*jsonrpc.Response)
	if !ok {
		return msg
	}
	key := idKey(resp.ID)
	s.mu.Lock()
	isList := s.lists[key]
	delete(s.lists, key)
	call := s.calls[key]
	delete(s.calls, key)
	s.mu.Unlock()

	switch {
	case isList:
		return s.handleListResult(ctx, resp)
	case call != nil:
		s.finishCall(ctx, call, resp)
	}
	return msg
}

// Close cancels pending approvals and ends open spans.
func (s *Session) Close() {
	s.mu.Lock()
	s.closed = true
	cancels := s.cancels
	calls := s.calls
	s.cancels = map[string]context.CancelFunc{}
	s.calls = map[string]*pendingCall{}
	s.mu.Unlock()
	for _, c := range cancels {
		c()
	}
	for _, c := range calls {
		c.span.End(context.Background(), "tollgate.session_closed", "session closed before upstream answered")
	}
}

func idKey(id jsonrpc.ID) string {
	return fmt.Sprintf("%T:%v", id.Raw(), id.Raw())
}

func idString(id jsonrpc.ID) string { return fmt.Sprint(id.Raw()) }
