// Package approval asks a human to approve a tool call.
//
// The Approver interface keeps the transport open: v0.1 ships CLIApprover,
// which queues requests in the state database and waits for a decision made
// with `roro approvals` in another terminal. A Slack or Telegram approver
// would implement the same interface.
package approval

import (
	"context"
	"time"
)

// Request is what a human sees. It carries the raw tool name and the
// (redacted) arguments exactly as the agent sent them, not a model-written
// summary (OWASP ASI09).
type Request struct {
	ID        string
	Agent     string
	Server    string
	Tool      string
	ArgsJSON  string // redacted arguments, pretty-printed JSON
	Reason    string // policy reason code that triggered approval
	PolicyIDs []string
	Created   time.Time
	Expires   time.Time
}

// Status of a request.
type Status string

// Statuses.
const (
	StatusPending   Status = "pending"
	StatusApproved  Status = "approved"
	StatusDenied    Status = "denied"
	StatusExpired   Status = "expired"
	StatusCancelled Status = "cancelled"
)

// Result is the outcome of an approval request.
type Result struct {
	Status    Status
	DecidedBy string
}

// Approved reports whether the call may proceed.
func (r Result) Approved() bool { return r.Status == StatusApproved }

// Approver obtains a human decision.
//
// RequestApproval blocks until a decision, req.Expires, or ctx cancellation.
// A timeout returns StatusExpired (callers deny). Cancellation returns
// StatusCancelled together with ctx.Err().
type Approver interface {
	RequestApproval(ctx context.Context, req Request) (Result, error)
}

// Func adapts a function to Approver (useful in tests and embeddings).
type Func func(ctx context.Context, req Request) (Result, error)

// RequestApproval implements Approver.
func (f Func) RequestApproval(ctx context.Context, req Request) (Result, error) { return f(ctx, req) }
