package audit

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"
)

const eventColumns = `seq, ts, kind, agent, server, tool, call_id, session, args_hash, args_preview,
	decision, reason, policy_ids, approval_id, latency_ms, result_digest, detail, prev_hash, entry_hash`

func scanEvent(row interface{ Scan(...any) error }) (Event, error) {
	var e Event
	var ts string
	err := row.Scan(&e.Seq, &ts, &e.Kind, &e.Agent, &e.Server, &e.Tool, &e.CallID, &e.Session,
		&e.ArgsHash, &e.ArgsPreview, &e.Decision, &e.Reason, &e.PolicyIDs, &e.ApprovalID,
		&e.LatencyMS, &e.ResultDigest, &e.Detail, &e.PrevHash, &e.EntryHash)
	if err != nil {
		return Event{}, err
	}
	e.Time, err = time.Parse(TimeFormat, ts)
	if err != nil {
		return Event{}, fmt.Errorf("event %d: bad timestamp %q", e.Seq, ts)
	}
	return e, nil
}

// Filter selects events for `tollgate logs`.
type Filter struct {
	Agent    string
	Tool     string
	Kind     string
	Decision string
	Since    time.Time
	Limit    int // most recent N; 0 = all
}

// Query returns matching events in ascending seq order.
func Query(ctx context.Context, db *sql.DB, f Filter) ([]Event, error) {
	var where []string
	var args []any
	add := func(cond string, v any) { where = append(where, cond); args = append(args, v) }
	if f.Agent != "" {
		add("agent = ?", f.Agent)
	}
	if f.Tool != "" {
		add("tool = ?", f.Tool)
	}
	if f.Kind != "" {
		add("kind = ?", f.Kind)
	}
	if f.Decision != "" {
		add("decision = ?", f.Decision)
	}
	if !f.Since.IsZero() {
		add("ts >= ?", f.Since.UTC().Format(TimeFormat))
	}
	q := "SELECT " + eventColumns + " FROM events"
	if len(where) > 0 {
		q += " WHERE " + strings.Join(where, " AND ")
	}
	q += " ORDER BY seq DESC"
	if f.Limit > 0 {
		q += fmt.Sprintf(" LIMIT %d", f.Limit)
	}
	rows, err := db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("audit: query: %w", err)
	}
	defer rows.Close()
	var out []Event
	for rows.Next() {
		e, err := scanEvent(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out, nil
}

// Checkpoints returns all checkpoints in insertion order.
func Checkpoints(ctx context.Context, db *sql.DB) ([]Checkpoint, error) {
	rows, err := db.QueryContext(ctx, `SELECT id, seq, entry_hash, ts, key_id, signature FROM checkpoints ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("audit: read checkpoints: %w", err)
	}
	defer rows.Close()
	var out []Checkpoint
	for rows.Next() {
		var c Checkpoint
		var ts string
		if err := rows.Scan(&c.ID, &c.Seq, &c.EntryHash, &ts, &c.KeyID, &c.Signature); err != nil {
			return nil, err
		}
		if c.Time, err = time.Parse(TimeFormat, ts); err != nil {
			return nil, fmt.Errorf("checkpoint %d: bad timestamp %q", c.ID, ts)
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// exportRecord is one JSONL line: either an event or a checkpoint.
type exportRecord struct {
	Type       string      `json:"type"`
	Event      *Event      `json:"event,omitempty"`
	Checkpoint *Checkpoint `json:"checkpoint,omitempty"`
}

// Export writes every event, then every checkpoint, as JSON Lines. Exported
// records carry their hashes and signatures, so they can be checked offline.
func Export(ctx context.Context, db *sql.DB, w io.Writer) (int, error) {
	rows, err := db.QueryContext(ctx, "SELECT "+eventColumns+" FROM events ORDER BY seq")
	if err != nil {
		return 0, fmt.Errorf("audit: export: %w", err)
	}
	defer rows.Close()
	enc := json.NewEncoder(w)
	n := 0
	for rows.Next() {
		e, err := scanEvent(rows)
		if err != nil {
			return n, err
		}
		if err := enc.Encode(exportRecord{Type: "event", Event: &e}); err != nil {
			return n, err
		}
		n++
	}
	if err := rows.Err(); err != nil {
		return n, err
	}
	cps, err := Checkpoints(ctx, db)
	if err != nil {
		return n, err
	}
	for i := range cps {
		if err := enc.Encode(exportRecord{Type: "checkpoint", Checkpoint: &cps[i]}); err != nil {
			return n, err
		}
	}
	return n, nil
}
