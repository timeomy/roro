// Package pin implements tool-definition pinning (trust on first use).
//
// The first time Roro sees a tool in a tools/list response it records a
// hash of the tool's name, title, description, input/output schemas, and
// annotations. If a later listing changes any of those, the tool is marked
// "changed" until a human accepts the new definition with `roro pins
// accept`. In block mode a changed tool is hidden from tools/list and calls to
// it are denied, because a silently edited description is itself a
// prompt-injection channel (tool poisoning, "rug pull").
//
// Inspired by the approach of Invariant mcp-scan / Snyk agent-scan; this is an
// independent implementation.
package pin

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/timeomy/roro/internal/store"
)

// Schema creates the pin table.
var Schema = []string{
	`CREATE TABLE IF NOT EXISTS tool_pins (
		server TEXT NOT NULL,
		tool TEXT NOT NULL,
		hash TEXT NOT NULL,
		definition TEXT NOT NULL,
		pending_hash TEXT NOT NULL DEFAULT '',
		pending_definition TEXT NOT NULL DEFAULT '',
		first_seen TEXT NOT NULL,
		changed_at TEXT NOT NULL DEFAULT '',
		PRIMARY KEY (server, tool)
	)`,
}

// Statuses reported to policy as context.pin_status.
const (
	StatusPinned  = "pinned"  // matches the accepted definition
	StatusChanged = "changed" // differs from the accepted definition
	StatusUnknown = "unknown" // never listed through Roro
)

// pinnedFields are the tool properties covered by the hash.
var pinnedFields = []string{"name", "title", "description", "inputSchema", "outputSchema", "annotations"}

// Tool is a tool definition as it appears in tools/list.
type Tool struct {
	Name string
	// Raw is the tool's full JSON object.
	Raw json.RawMessage
}

// Change describes a difference found by Observe.
type Change struct {
	Server, Tool       string
	Kind               string // "new" or "changed" or "restored"
	OldHash, NewHash   string
	OldDefinition, New string
}

// Canonical returns the canonical JSON of the pinned fields and its hash.
// Keys are sorted (encoding/json sorts map keys) and numbers are kept as
// written.
func Canonical(raw json.RawMessage) (canonical string, hash string, err error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var obj map[string]any
	if err := dec.Decode(&obj); err != nil {
		return "", "", fmt.Errorf("pin: tool definition is not a JSON object: %w", err)
	}
	picked := map[string]any{}
	for _, f := range pinnedFields {
		if v, ok := obj[f]; ok {
			picked[f] = v
		}
	}
	b, err := json.Marshal(picked)
	if err != nil {
		return "", "", err
	}
	sum := sha256.Sum256(b)
	return string(b), hex.EncodeToString(sum[:]), nil
}

// Store persists pins.
type Store struct {
	db  *sql.DB
	now func() time.Time
}

// New returns a Store over a database with Schema applied.
func New(db *sql.DB) *Store { return &Store{db: db, now: time.Now} }

// Observe records a tools/list result and returns what changed.
func (s *Store) Observe(ctx context.Context, server string, tools []Tool) ([]Change, error) {
	var changes []Change
	err := store.InTx(ctx, s.db, func(tx *sql.Tx) error {
		for _, t := range tools {
			c, err := s.observeOne(ctx, tx, server, t)
			if err != nil {
				return err
			}
			if c != nil {
				changes = append(changes, *c)
			}
		}
		return nil
	})
	return changes, err
}

func (s *Store) observeOne(ctx context.Context, tx *sql.Tx, server string, t Tool) (*Change, error) {
	def, h, err := Canonical(t.Raw)
	if err != nil {
		return nil, err
	}
	now := s.now().UTC().Format(time.RFC3339Nano)
	var oldHash, oldDef, pending string
	err = tx.QueryRowContext(ctx, `SELECT hash, definition, pending_hash FROM tool_pins WHERE server=? AND tool=?`,
		server, t.Name).Scan(&oldHash, &oldDef, &pending)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		_, err = tx.ExecContext(ctx, `INSERT INTO tool_pins (server, tool, hash, definition, first_seen) VALUES (?,?,?,?,?)`,
			server, t.Name, h, def, now)
		return &Change{Server: server, Tool: t.Name, Kind: "new", NewHash: h, New: def}, wrap(err)
	case err != nil:
		return nil, wrap(err)
	case h == oldHash:
		if pending == "" {
			return nil, nil
		}
		_, err = tx.ExecContext(ctx, `UPDATE tool_pins SET pending_hash='', pending_definition='', changed_at='' WHERE server=? AND tool=?`, server, t.Name)
		return &Change{Server: server, Tool: t.Name, Kind: "restored", OldHash: pending, NewHash: h}, wrap(err)
	case h == pending:
		return nil, nil // already recorded
	default:
		_, err = tx.ExecContext(ctx, `UPDATE tool_pins SET pending_hash=?, pending_definition=?, changed_at=? WHERE server=? AND tool=?`,
			h, def, now, server, t.Name)
		return &Change{Server: server, Tool: t.Name, Kind: "changed", OldHash: oldHash, NewHash: h, OldDefinition: oldDef, New: def}, wrap(err)
	}
}

// Status returns the pin status of a tool. Errors report StatusChanged so a
// caller that ignores the error still fails closed in block mode.
func (s *Store) Status(ctx context.Context, server, tool string) (string, error) {
	var pending string
	err := s.db.QueryRowContext(ctx, `SELECT pending_hash FROM tool_pins WHERE server=? AND tool=?`, server, tool).Scan(&pending)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return StatusUnknown, nil
	case err != nil:
		return StatusChanged, wrap(err)
	case pending != "":
		return StatusChanged, nil
	default:
		return StatusPinned, nil
	}
}

// Accept makes the pending definition of a tool the pinned one.
func (s *Store) Accept(ctx context.Context, server, tool string) (Change, error) {
	var c Change
	err := store.InTx(ctx, s.db, func(tx *sql.Tx) error {
		var oldHash, pending, pendingDef string
		err := tx.QueryRowContext(ctx, `SELECT hash, pending_hash, pending_definition FROM tool_pins WHERE server=? AND tool=?`,
			server, tool).Scan(&oldHash, &pending, &pendingDef)
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("pin: no pin for %s/%s", server, tool)
		}
		if err != nil {
			return wrap(err)
		}
		if pending == "" {
			return fmt.Errorf("pin: %s/%s has no pending change", server, tool)
		}
		_, err = tx.ExecContext(ctx, `UPDATE tool_pins SET hash=?, definition=?, pending_hash='', pending_definition='', changed_at='' WHERE server=? AND tool=?`,
			pending, pendingDef, server, tool)
		c = Change{Server: server, Tool: tool, Kind: "accepted", OldHash: oldHash, NewHash: pending}
		return wrap(err)
	})
	return c, err
}

// Entry is one pin as listed by `roro pins list`.
type Entry struct {
	Server, Tool, Hash, PendingHash, FirstSeen, ChangedAt string
}

// List returns every pin.
func (s *Store) List(ctx context.Context) ([]Entry, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT server, tool, hash, pending_hash, first_seen, changed_at FROM tool_pins ORDER BY server, tool`)
	if err != nil {
		return nil, wrap(err)
	}
	defer rows.Close()
	var out []Entry
	for rows.Next() {
		var e Entry
		if err := rows.Scan(&e.Server, &e.Tool, &e.Hash, &e.PendingHash, &e.FirstSeen, &e.ChangedAt); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func wrap(err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("pin: %w", err)
}
