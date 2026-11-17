// Package killswitch stops tool calls globally or for one agent.
//
// State lives in the shared state database, so `roro kill` in one
// terminal affects every running Roro process on the next tool call, and
// survives restarts. If the state cannot be read, the switch reports active
// (fail closed).
package killswitch

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/timeomy/roro/internal/store"
)

// Schema creates the kill switch table.
var Schema = []string{
	`CREATE TABLE IF NOT EXISTS kill_switch (
		scope TEXT PRIMARY KEY,
		active INTEGER NOT NULL,
		reason TEXT NOT NULL DEFAULT '',
		actor TEXT NOT NULL DEFAULT '',
		updated_at TEXT NOT NULL
	)`,
}

// GlobalScope is the scope key of the global switch.
const GlobalScope = "*"

// Scope returns the scope key for an agent ("" means global).
func Scope(agent string) string {
	if agent == "" {
		return GlobalScope
	}
	return "agent:" + agent
}

// Status describes the switch state for one agent.
type Status struct {
	Active bool
	Scope  string // which switch is active: GlobalScope or "agent:<name>"
	Reason string
}

// Entry is one row of switch state.
type Entry struct {
	Scope     string
	Active    bool
	Reason    string
	Actor     string
	UpdatedAt time.Time
}

// Switch reads and writes kill switch state.
type Switch struct {
	db  *sql.DB
	now func() time.Time
}

// New returns a Switch over a state database that has Schema applied.
func New(db *sql.DB) *Switch { return &Switch{db: db, now: time.Now} }

// Kill activates the switch for agent ("" = global).
func (s *Switch) Kill(ctx context.Context, agent, reason, actor string) error {
	return s.set(ctx, agent, true, reason, actor)
}

// Resume deactivates the switch for agent ("" = global). Resuming the global
// switch does not clear per-agent switches.
func (s *Switch) Resume(ctx context.Context, agent, reason, actor string) error {
	return s.set(ctx, agent, false, reason, actor)
}

func (s *Switch) set(ctx context.Context, agent string, active bool, reason, actor string) error {
	return store.InTx(ctx, s.db, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO kill_switch (scope, active, reason, actor, updated_at)
			VALUES (?, ?, ?, ?, ?)
			ON CONFLICT(scope) DO UPDATE SET active=excluded.active, reason=excluded.reason,
				actor=excluded.actor, updated_at=excluded.updated_at`,
			Scope(agent), boolToInt(active), reason, actor, s.now().UTC().Format(time.RFC3339Nano))
		if err != nil {
			return fmt.Errorf("killswitch: %w", err)
		}
		return nil
	})
}

// Check returns the state for agent. On any error it returns an active
// status together with the error, so callers that ignore the error still
// fail closed.
func (s *Switch) Check(ctx context.Context, agent string) (Status, error) {
	for _, scope := range []string{GlobalScope, Scope(agent)} {
		var active int
		var reason string
		err := s.db.QueryRowContext(ctx, `SELECT active, reason FROM kill_switch WHERE scope = ?`, scope).Scan(&active, &reason)
		if errors.Is(err, sql.ErrNoRows) {
			continue
		}
		if err != nil {
			return Status{Active: true, Scope: "unknown", Reason: "kill switch state unreadable"},
				fmt.Errorf("killswitch: %w", err)
		}
		if active == 1 {
			return Status{Active: true, Scope: scope, Reason: reason}, nil
		}
	}
	return Status{}, nil
}

// List returns every switch row.
func (s *Switch) List(ctx context.Context) ([]Entry, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT scope, active, reason, actor, updated_at FROM kill_switch ORDER BY scope`)
	if err != nil {
		return nil, fmt.Errorf("killswitch: %w", err)
	}
	defer rows.Close()
	var out []Entry
	for rows.Next() {
		var e Entry
		var active int
		var ts string
		if err := rows.Scan(&e.Scope, &active, &e.Reason, &e.Actor, &ts); err != nil {
			return nil, err
		}
		e.Active = active == 1
		e.UpdatedAt, _ = time.Parse(time.RFC3339Nano, ts)
		out = append(out, e)
	}
	return out, rows.Err()
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
