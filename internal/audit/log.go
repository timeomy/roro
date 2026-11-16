package audit

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/timeomy/tollgate/internal/store"
)

// Log is the audit log interface the proxy depends on.
type Log interface {
	// Append adds an event, filling Seq, Time (if zero), PrevHash, and
	// EntryHash. It returns the stored event.
	Append(ctx context.Context, e Event) (Event, error)
	// Checkpoint signs the current head of the chain. It is a no-op if the
	// head is already checkpointed or the log is empty.
	Checkpoint(ctx context.Context) error
	Close() error
}

var schema = []string{
	`CREATE TABLE IF NOT EXISTS events (
		seq INTEGER PRIMARY KEY,
		ts TEXT NOT NULL,
		kind TEXT NOT NULL,
		agent TEXT NOT NULL DEFAULT '',
		server TEXT NOT NULL DEFAULT '',
		tool TEXT NOT NULL DEFAULT '',
		call_id TEXT NOT NULL DEFAULT '',
		session TEXT NOT NULL DEFAULT '',
		args_hash TEXT NOT NULL DEFAULT '',
		args_preview TEXT NOT NULL DEFAULT '',
		decision TEXT NOT NULL DEFAULT '',
		reason TEXT NOT NULL DEFAULT '',
		policy_ids TEXT NOT NULL DEFAULT '',
		approval_id TEXT NOT NULL DEFAULT '',
		latency_ms INTEGER NOT NULL DEFAULT 0,
		result_digest TEXT NOT NULL DEFAULT '',
		detail TEXT NOT NULL DEFAULT '',
		prev_hash TEXT NOT NULL,
		entry_hash TEXT NOT NULL
	)`,
	`CREATE INDEX IF NOT EXISTS events_agent_ts ON events(agent, ts)`,
	`CREATE TABLE IF NOT EXISTS checkpoints (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		seq INTEGER NOT NULL,
		entry_hash TEXT NOT NULL,
		ts TEXT NOT NULL,
		key_id TEXT NOT NULL,
		signature TEXT NOT NULL
	)`,
	// Append-only at the SQL layer. This stops accidental edits through the
	// normal API; it does not stop someone with file access, which is what
	// the hash chain and signatures are for.
	`CREATE TRIGGER IF NOT EXISTS events_no_update BEFORE UPDATE ON events
		BEGIN SELECT RAISE(ABORT, 'audit events are append-only'); END`,
	`CREATE TRIGGER IF NOT EXISTS events_no_delete BEFORE DELETE ON events
		BEGIN SELECT RAISE(ABORT, 'audit events are append-only'); END`,
	`CREATE TRIGGER IF NOT EXISTS checkpoints_no_update BEFORE UPDATE ON checkpoints
		BEGIN SELECT RAISE(ABORT, 'checkpoints are append-only'); END`,
	`CREATE TRIGGER IF NOT EXISTS checkpoints_no_delete BEFORE DELETE ON checkpoints
		BEGIN SELECT RAISE(ABORT, 'checkpoints are append-only'); END`,
}

// HashChainSQLiteLog is the v0.1 Log implementation.
type HashChainSQLiteLog struct {
	db              *sql.DB
	signer          *Signer
	checkpointEvery int64
	now             func() time.Time
}

// Options configures OpenLog.
type Options struct {
	Path            string
	Signer          *Signer
	CheckpointEvery int
	// Now overrides the clock (tests).
	Now func() time.Time
}

// OpenLog opens or creates the audit database. A signer is required: an
// unsigned log could not prove anything about truncation.
func OpenLog(ctx context.Context, opts Options) (*HashChainSQLiteLog, error) {
	if opts.Signer == nil {
		return nil, errors.New("audit: a signing key is required")
	}
	if opts.CheckpointEvery < 1 {
		opts.CheckpointEvery = 100
	}
	db, err := store.Open(ctx, opts.Path, schema...)
	if err != nil {
		return nil, err
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	return &HashChainSQLiteLog{db: db, signer: opts.Signer, checkpointEvery: int64(opts.CheckpointEvery), now: now}, nil
}

// Append implements Log. The read of the chain head and the insert happen in
// one immediate transaction, so concurrent processes cannot fork the chain.
func (l *HashChainSQLiteLog) Append(ctx context.Context, e Event) (Event, error) {
	var stored Event
	err := store.InTx(ctx, l.db, func(tx *sql.Tx) error {
		seq, prev, err := head(ctx, tx)
		if err != nil {
			return err
		}
		e.Seq = seq + 1
		e.PrevHash = prev
		if e.Time.IsZero() {
			e.Time = l.now()
		}
		e.Time = e.Time.UTC()
		e.EntryHash = e.ComputeHash()
		if err := insertEvent(ctx, tx, e); err != nil {
			return err
		}
		if e.Seq%l.checkpointEvery == 0 {
			if err := l.checkpointTx(ctx, tx); err != nil {
				return err
			}
		}
		stored = e
		return nil
	})
	if err != nil {
		return Event{}, fmt.Errorf("audit: append: %w", err)
	}
	return stored, nil
}

// Checkpoint implements Log.
func (l *HashChainSQLiteLog) Checkpoint(ctx context.Context) error {
	return store.InTx(ctx, l.db, func(tx *sql.Tx) error { return l.checkpointTx(ctx, tx) })
}

func (l *HashChainSQLiteLog) checkpointTx(ctx context.Context, tx *sql.Tx) error {
	seq, h, err := head(ctx, tx)
	if err != nil || seq == 0 {
		return err
	}
	var last sql.NullInt64
	if err := tx.QueryRowContext(ctx, `SELECT MAX(seq) FROM checkpoints`).Scan(&last); err != nil {
		return fmt.Errorf("audit: read checkpoints: %w", err)
	}
	if last.Valid && last.Int64 >= seq {
		return nil
	}
	c := l.signer.Sign(Checkpoint{Seq: seq, EntryHash: h, Time: l.now().UTC()})
	_, err = tx.ExecContext(ctx,
		`INSERT INTO checkpoints (seq, entry_hash, ts, key_id, signature) VALUES (?, ?, ?, ?, ?)`,
		c.Seq, c.EntryHash, c.Time.Format(TimeFormat), c.KeyID, c.Signature)
	if err != nil {
		return fmt.Errorf("audit: write checkpoint: %w", err)
	}
	return nil
}

// Close writes a final checkpoint and closes the database.
func (l *HashChainSQLiteLog) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cpErr := l.Checkpoint(ctx)
	return errors.Join(cpErr, l.db.Close())
}

func head(ctx context.Context, tx *sql.Tx) (int64, string, error) {
	var seq int64
	var h string
	err := tx.QueryRowContext(ctx, `SELECT seq, entry_hash FROM events ORDER BY seq DESC LIMIT 1`).Scan(&seq, &h)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, GenesisHash, nil
	}
	if err != nil {
		return 0, "", fmt.Errorf("audit: read chain head: %w", err)
	}
	return seq, h, nil
}

func insertEvent(ctx context.Context, tx *sql.Tx, e Event) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO events (seq, ts, kind, agent, server, tool, call_id, session,
		args_hash, args_preview, decision, reason, policy_ids, approval_id, latency_ms, result_digest,
		detail, prev_hash, entry_hash) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		e.Seq, e.Time.Format(TimeFormat), e.Kind, e.Agent, e.Server, e.Tool, e.CallID, e.Session,
		e.ArgsHash, e.ArgsPreview, e.Decision, e.Reason, e.PolicyIDs, e.ApprovalID, e.LatencyMS,
		e.ResultDigest, e.Detail, e.PrevHash, e.EntryHash)
	if err != nil {
		return fmt.Errorf("audit: insert event: %w", err)
	}
	return nil
}
