package store

import (
	"os"
	"path/filepath"
	"testing"
)

// A log copied to read-only media must still be readable by verify.
func TestOpenReadOnlyDoesNotWrite(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "ro")
	path := filepath.Join(dir, "audit.db")
	db, err := Open(t.Context(), path, `CREATE TABLE t (x INTEGER)`, `INSERT INTO t VALUES (42)`)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(path)
	if err := os.Chmod(path, 0o444); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })

	ro, err := OpenReadOnly(t.Context(), path)
	if err != nil {
		t.Fatalf("OpenReadOnly on read-only dir: %v", err)
	}
	defer ro.Close()
	var x int
	if err := ro.QueryRow(`SELECT x FROM t`).Scan(&x); err != nil || x != 42 {
		t.Fatalf("read: x=%d err=%v", x, err)
	}
	if _, err := ro.Exec(`INSERT INTO t VALUES (1)`); err == nil {
		t.Fatal("write succeeded on a read-only handle")
	}
	after, _ := os.ReadFile(path)
	if string(before) != string(after) {
		t.Fatal("database file changed")
	}
	if _, err := OpenReadOnly(t.Context(), filepath.Join(dir, "missing.db")); err == nil {
		t.Fatal("missing file opened")
	}
}
