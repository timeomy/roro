// Package store opens the SQLite databases Tollgate uses for its audit log and
// runtime state. It uses the pure-Go modernc.org/sqlite driver, so Tollgate
// builds with CGO_ENABLED=0.
package store

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	_ "modernc.org/sqlite" // registers the "sqlite" driver
)

// Open opens (creating if needed) the SQLite database at path and applies
// schema. Write transactions take the lock immediately (BEGIN IMMEDIATE), so
// several Tollgate processes can safely share one database.
func Open(ctx context.Context, path string, schema ...string) (*sql.DB, error) {
	if path == "" {
		return nil, fmt.Errorf("store: empty database path")
	}
	if strings.ContainsAny(path, "?#") {
		return nil, fmt.Errorf("store: database path %q must not contain '?' or '#'", path)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("store: create directory for %s: %w", path, err)
	}
	dsn := "file:" + filepath.ToSlash(path) +
		"?_txlock=immediate" +
		"&_pragma=busy_timeout(10000)" +
		"&_pragma=journal_mode(WAL)" +
		"&_pragma=synchronous(FULL)" +
		"&_pragma=foreign_keys(1)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("store: open %s: %w", path, err)
	}
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("store: open %s: %w", path, err)
	}
	for _, stmt := range schema {
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("store: apply schema to %s: %w", path, err)
		}
	}
	return db, nil
}

// OpenExisting opens a database that must already exist. It is used by
// read-side commands (verify, logs, export) so a typo in a path does not
// silently create an empty, "valid" log.
func OpenExisting(ctx context.Context, path string) (*sql.DB, error) {
	if _, err := os.Stat(path); err != nil {
		return nil, fmt.Errorf("store: %w", err)
	}
	return Open(ctx, path)
}

// OpenReadOnly opens an existing database without writing to it: no schema,
// no journal-mode change. verify, logs and export use it, so auditing a
// copy of a log (even on read-only media) never modifies it.
func OpenReadOnly(ctx context.Context, path string) (*sql.DB, error) {
	if _, err := os.Stat(path); err != nil {
		return nil, fmt.Errorf("store: %w", err)
	}
	if strings.ContainsAny(path, "?#") {
		return nil, fmt.Errorf("store: database path %q must not contain '?' or '#'", path)
	}
	base := "file:" + filepath.ToSlash(path) + "?mode=ro&_pragma=busy_timeout(10000)"
	db, err := openProbe(ctx, base)
	if err != nil {
		// A WAL database needs its -shm file, which SQLite cannot create in
		// a read-only directory. Nothing can be writing to a file there, so
		// reading it as immutable is safe.
		db, err = openProbe(ctx, base+"&immutable=1")
	}
	if err != nil {
		return nil, fmt.Errorf("store: open %s read-only: %w", path, err)
	}
	return db, nil
}

func openProbe(ctx context.Context, dsn string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	var n int
	if err := db.QueryRowContext(ctx, "SELECT count(*) FROM sqlite_master").Scan(&n); err != nil {
		_ = db.Close()
		return nil, err
	}
	return db, nil
}

// InTx runs fn in a write transaction and commits it if fn returns nil.
func InTx(ctx context.Context, db *sql.DB, fn func(*sql.Tx) error) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: begin: %w", err)
	}
	if err := fn(tx); err != nil {
		_ = tx.Rollback()
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: commit: %w", err)
	}
	return nil
}
