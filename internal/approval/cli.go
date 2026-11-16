package approval

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/timeomy/tollgate/internal/store"
)

// Schema creates the approval queue table.
var Schema = []string{
	`CREATE TABLE IF NOT EXISTS approvals (
		id TEXT PRIMARY KEY,
		created_at TEXT NOT NULL,
		expires_at TEXT NOT NULL,
		agent TEXT NOT NULL,
		server TEXT NOT NULL,
		tool TEXT NOT NULL,
		args_json TEXT NOT NULL,
		reason TEXT NOT NULL,
		policy_ids TEXT NOT NULL,
		status TEXT NOT NULL,
		decided_by TEXT NOT NULL DEFAULT '',
		decided_at TEXT NOT NULL DEFAULT ''
	)`,
	`CREATE INDEX IF NOT EXISTS approvals_status ON approvals(status, created_at)`,
}

const timeFmt = time.RFC3339Nano

// CLIApprover queues approval requests in the state database. A human
// decides with `tollgate approvals watch` (interactive prompt) or
// `tollgate approvals approve|deny ID`.
type CLIApprover struct {
	db   *sql.DB
	poll time.Duration
	now  func() time.Time
}

// NewCLIApprover returns an approver over a database with Schema applied.
func NewCLIApprover(db *sql.DB) *CLIApprover {
	return &CLIApprover{db: db, poll: 200 * time.Millisecond, now: time.Now}
}

// NewID returns a short random approval id.
func NewID() string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// RequestApproval implements Approver.
func (a *CLIApprover) RequestApproval(ctx context.Context, req Request) (Result, error) {
	if req.ID == "" {
		req.ID = NewID()
	}
	if req.Created.IsZero() {
		req.Created = a.now()
	}
	if !req.Expires.After(req.Created) {
		return Result{Status: StatusExpired}, errors.New("approval: request expires before it is created")
	}
	if err := a.insert(ctx, req); err != nil {
		return Result{Status: StatusDenied}, err
	}
	ticker := time.NewTicker(a.poll)
	defer ticker.Stop()
	deadline := time.NewTimer(time.Until(req.Expires))
	defer deadline.Stop()
	for {
		res, done, err := a.status(ctx, req.ID)
		if err != nil {
			if ctx.Err() != nil {
				a.finish(req.ID, StatusCancelled)
				return Result{Status: StatusCancelled}, ctx.Err()
			}
			return Result{Status: StatusDenied}, err
		}
		if done {
			return res, nil
		}
		select {
		case <-ctx.Done():
			a.finish(req.ID, StatusCancelled)
			return Result{Status: StatusCancelled}, ctx.Err()
		case <-deadline.C:
			// A decision may have raced the deadline; finish only if pending.
			if a.finish(req.ID, StatusExpired) {
				return Result{Status: StatusExpired}, nil
			}
		case <-ticker.C:
		}
	}
}

func (a *CLIApprover) insert(ctx context.Context, r Request) error {
	return store.InTx(ctx, a.db, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO approvals (id, created_at, expires_at, agent, server, tool, args_json, reason, policy_ids, status)
			VALUES (?,?,?,?,?,?,?,?,?,?)`,
			r.ID, r.Created.UTC().Format(timeFmt), r.Expires.UTC().Format(timeFmt), r.Agent, r.Server, r.Tool,
			r.ArgsJSON, r.Reason, strings.Join(r.PolicyIDs, ","), StatusPending)
		if err != nil {
			return fmt.Errorf("approval: queue request: %w", err)
		}
		return nil
	})
}

func (a *CLIApprover) status(ctx context.Context, id string) (Result, bool, error) {
	var st, by string
	err := a.db.QueryRowContext(ctx, `SELECT status, decided_by FROM approvals WHERE id=?`, id).Scan(&st, &by)
	if err != nil {
		return Result{}, false, fmt.Errorf("approval: read request %s: %w", id, err)
	}
	if Status(st) == StatusPending {
		return Result{}, false, nil
	}
	return Result{Status: Status(st), DecidedBy: by}, true, nil
}

// finish moves a still-pending request to a terminal status. It uses a fresh
// context so cancellation of the caller does not leave the row pending.
func (a *CLIApprover) finish(id string, st Status) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	res, err := a.db.ExecContext(ctx, `UPDATE approvals SET status=?, decided_by='tollgate', decided_at=? WHERE id=? AND status='pending'`,
		st, a.now().UTC().Format(timeFmt), id)
	if err != nil {
		return false
	}
	n, _ := res.RowsAffected()
	return n == 1
}

// Decide records a human decision. It fails if the request is unknown, no
// longer pending, or expired.
func Decide(ctx context.Context, db *sql.DB, id string, approve bool, decidedBy string) error {
	st := StatusDenied
	if approve {
		st = StatusApproved
	}
	now := time.Now().UTC().Format(timeFmt)
	res, err := db.ExecContext(ctx, `UPDATE approvals SET status=?, decided_by=?, decided_at=?
		WHERE id=? AND status='pending' AND expires_at > ?`, st, decidedBy, now, id, now)
	if err != nil {
		return fmt.Errorf("approval: %w", err)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return fmt.Errorf("approval: %s is not pending (unknown, already decided, or expired)", id)
	}
	return nil
}

// Pending lists requests waiting for a decision, oldest first.
func Pending(ctx context.Context, db *sql.DB) ([]Request, error) {
	now := time.Now().UTC().Format(timeFmt)
	rows, err := db.QueryContext(ctx, `SELECT id, created_at, expires_at, agent, server, tool, args_json, reason, policy_ids
		FROM approvals WHERE status='pending' AND expires_at > ? ORDER BY created_at`, now)
	if err != nil {
		return nil, fmt.Errorf("approval: %w", err)
	}
	defer rows.Close()
	var out []Request
	for rows.Next() {
		var r Request
		var created, expires, ids string
		if err := rows.Scan(&r.ID, &created, &expires, &r.Agent, &r.Server, &r.Tool, &r.ArgsJSON, &r.Reason, &ids); err != nil {
			return nil, err
		}
		r.Created, _ = time.Parse(timeFmt, created)
		r.Expires, _ = time.Parse(timeFmt, expires)
		if ids != "" {
			r.PolicyIDs = strings.Split(ids, ",")
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
