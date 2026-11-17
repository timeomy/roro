package audit

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/timeomy/tollgate/internal/store"
)

type fixture struct {
	dir    string
	log    *HashChainSQLiteLog
	signer *Signer
	pubKey string
}

func newFixture(t *testing.T, every int) *fixture {
	t.Helper()
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "k.key")
	if _, err := GenerateKey(keyPath); err != nil {
		t.Fatal(err)
	}
	signer, err := LoadSigner(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	clock := time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)
	l, err := OpenLog(t.Context(), Options{
		Path: filepath.Join(dir, "audit.db"), Signer: signer, CheckpointEvery: every,
		Now: func() time.Time { clock = clock.Add(time.Second); return clock },
	})
	if err != nil {
		t.Fatal(err)
	}
	return &fixture{dir: dir, log: l, signer: signer, pubKey: keyPath + ".pub"}
}

func (f *fixture) appendN(t *testing.T, n int) {
	t.Helper()
	for i := range n {
		_, err := f.log.Append(t.Context(), Event{Kind: KindToolCall, Agent: "a", Tool: "echo",
			Decision: "allow", Reason: "permitted", CallID: string(rune('0' + i%10))})
		if err != nil {
			t.Fatal(err)
		}
	}
}

// raw opens the database directly and drops the append-only triggers,
// simulating an attacker with write access to the file.
func (f *fixture) raw(t *testing.T) *sql.DB {
	t.Helper()
	db, err := store.Open(t.Context(), filepath.Join(f.dir, "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	for _, trg := range []string{"events_no_update", "events_no_delete", "checkpoints_no_update", "checkpoints_no_delete"} {
		if _, err := db.Exec("DROP TRIGGER " + trg); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func (f *fixture) verify(t *testing.T, sealed bool) Report {
	t.Helper()
	pub, err := LoadPublicKey(f.pubKey)
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.OpenExisting(t.Context(), filepath.Join(f.dir, "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rep, err := Verify(t.Context(), db, VerifyOptions{PublicKey: pub, RequireSealed: sealed})
	if err != nil {
		t.Fatal(err)
	}
	return rep
}

func mustFail(t *testing.T, rep Report, want string) {
	t.Helper()
	if rep.OK() {
		t.Fatalf("verify passed, want failure mentioning %q", want)
	}
	if !strings.Contains(strings.Join(rep.Problems, "\n"), want) {
		t.Fatalf("problems %q do not mention %q", rep.Problems, want)
	}
}

func TestCleanLogVerifies(t *testing.T) {
	f := newFixture(t, 4)
	f.appendN(t, 10)
	if err := f.log.Close(); err != nil {
		t.Fatal(err)
	}
	rep := f.verify(t, true)
	if !rep.OK() {
		t.Fatalf("clean log failed: %v", rep.Problems)
	}
	if rep.Events != 10 || rep.LastSeq != 10 || rep.Checkpoints != 3 || rep.Unsealed != 0 {
		t.Fatalf("report = %+v, want 10 events, 3 checkpoints (4, 8, close at 10)", rep)
	}
}

func TestAppendOnlyTriggers(t *testing.T) {
	f := newFixture(t, 100)
	f.appendN(t, 2)
	if _, err := f.log.db.Exec(`UPDATE events SET decision='deny' WHERE seq=1`); err == nil {
		t.Fatal("UPDATE on events succeeded")
	}
	if _, err := f.log.db.Exec(`DELETE FROM events WHERE seq=2`); err == nil {
		t.Fatal("DELETE on events succeeded")
	}
}

func TestTamperedFieldDetected(t *testing.T) {
	f := newFixture(t, 100)
	f.appendN(t, 5)
	_ = f.log.Close()
	if _, err := f.raw(t).Exec(`UPDATE events SET decision='allow', reason='permitted', agent='other' WHERE seq=3`); err != nil {
		t.Fatal(err)
	}
	mustFail(t, f.verify(t, false), "seq 3: row was modified")
}

func TestTamperedFieldWithRecomputedHashDetected(t *testing.T) {
	// An attacker who recomputes the row hash still breaks the next link and
	// the signed checkpoint.
	f := newFixture(t, 100)
	f.appendN(t, 5)
	_ = f.log.Close()
	db := f.raw(t)
	e, err := scanEvent(db.QueryRow("SELECT " + eventColumns + " FROM events WHERE seq=3"))
	if err != nil {
		t.Fatal(err)
	}
	e.Decision = "deny"
	e.EntryHash = e.ComputeHash()
	if _, err := db.Exec(`UPDATE events SET decision=?, entry_hash=? WHERE seq=3`, e.Decision, e.EntryHash); err != nil {
		t.Fatal(err)
	}
	mustFail(t, f.verify(t, false), "seq 4: prev_hash does not match")
}

func TestDeletedRowDetected(t *testing.T) {
	f := newFixture(t, 100)
	f.appendN(t, 5)
	_ = f.log.Close()
	if _, err := f.raw(t).Exec(`DELETE FROM events WHERE seq=2`); err != nil {
		t.Fatal(err)
	}
	mustFail(t, f.verify(t, false), "missing or reordered rows")
}

func TestReorderedRowsDetected(t *testing.T) {
	f := newFixture(t, 100)
	f.appendN(t, 5)
	_ = f.log.Close()
	db := f.raw(t)
	for _, q := range []string{
		`UPDATE events SET seq=100 WHERE seq=2`,
		`UPDATE events SET seq=2 WHERE seq=3`,
		`UPDATE events SET seq=3 WHERE seq=100`,
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	mustFail(t, f.verify(t, false), "prev_hash does not match")
}

func TestTruncationDetected(t *testing.T) {
	f := newFixture(t, 100)
	f.appendN(t, 6)
	_ = f.log.Close() // checkpoint at seq 6
	if _, err := f.raw(t).Exec(`DELETE FROM events WHERE seq > 4`); err != nil {
		t.Fatal(err)
	}
	mustFail(t, f.verify(t, false), "truncation")
}

func TestForgedCheckpointDetected(t *testing.T) {
	f := newFixture(t, 100)
	f.appendN(t, 3)
	_ = f.log.Close()
	if _, err := f.raw(t).Exec(`UPDATE checkpoints SET seq=2`); err != nil {
		t.Fatal(err)
	}
	mustFail(t, f.verify(t, false), "invalid signature")
}

func TestWrongKeyDetected(t *testing.T) {
	f := newFixture(t, 100)
	f.appendN(t, 3)
	_ = f.log.Close()
	other := filepath.Join(t.TempDir(), "other.key")
	if _, err := GenerateKey(other); err != nil {
		t.Fatal(err)
	}
	f.pubKey = other + ".pub"
	mustFail(t, f.verify(t, false), "unknown key")
}

func TestUnsealedTail(t *testing.T) {
	f := newFixture(t, 100)
	f.appendN(t, 3)
	if err := f.log.Checkpoint(t.Context()); err != nil {
		t.Fatal(err)
	}
	f.appendN(t, 2) // not checkpointed; log left open
	rep := f.verify(t, false)
	if !rep.OK() || rep.Unsealed != 2 {
		t.Fatalf("report = %+v, want OK with 2 unsealed", rep)
	}
	mustFail(t, f.verify(t, true), "unsealed")
	_ = f.log.Close()
}

func TestNoCheckpointFails(t *testing.T) {
	f := newFixture(t, 100)
	f.appendN(t, 2)
	// Read without closing (no checkpoint yet).
	mustFail(t, f.verify(t, false), "no checkpoints")
	_ = f.log.Close()
}

func TestGenerateKeyRefusesOverwrite(t *testing.T) {
	p := filepath.Join(t.TempDir(), "k.key")
	if _, err := GenerateKey(p); err != nil {
		t.Fatal(err)
	}
	if _, err := GenerateKey(p); err == nil {
		t.Fatal("GenerateKey overwrote an existing key")
	}
	if _, err := LoadSigner(filepath.Join(t.TempDir(), "missing.key")); err == nil {
		t.Fatal("LoadSigner accepted a missing key")
	}
}

func TestQueryAndExport(t *testing.T) {
	f := newFixture(t, 100)
	ctx := context.Background()
	for _, d := range []string{"allow", "deny", "deny"} {
		if _, err := f.log.Append(ctx, Event{Kind: KindToolCall, Agent: "a", Tool: "t", Decision: d}); err != nil {
			t.Fatal(err)
		}
	}
	got, err := Query(ctx, f.log.db, Filter{Decision: "deny"})
	if err != nil || len(got) != 2 || got[0].Seq != 2 {
		t.Fatalf("Query = %+v, %v", got, err)
	}
	last, _ := Query(ctx, f.log.db, Filter{Limit: 1})
	if len(last) != 1 || last[0].Seq != 3 {
		t.Fatalf("Limit query = %+v", last)
	}
	_ = f.log.Checkpoint(ctx)
	var buf bytes.Buffer
	n, err := Export(ctx, f.log.db, &buf)
	if err != nil || n != 3 {
		t.Fatalf("Export = %d, %v", n, err)
	}
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 4 {
		t.Fatalf("export lines = %d, want 3 events + 1 checkpoint", len(lines))
	}
	var rec exportRecord
	if err := json.Unmarshal([]byte(lines[3]), &rec); err != nil || rec.Type != "checkpoint" {
		t.Fatalf("last export line = %s", lines[3])
	}
	_ = f.log.Close()
}

// Rolling the log back to an earlier checkpoint verifies on its own (the
// documented limit), but fails against an anchor recorded earlier.
func TestRollbackDetectedOnlyWithAnchor(t *testing.T) {
	f := newFixture(t, 3)
	f.appendN(t, 9) // checkpoints at 3, 6, 9
	_ = f.log.Close()
	before := f.verify(t, true)
	if !before.OK() || !strings.HasPrefix(before.Anchor, "9:") {
		t.Fatalf("before: ok=%v anchor=%q problems=%v", before.OK(), before.Anchor, before.Problems)
	}
	anchor, err := ParseAnchor(before.Anchor)
	if err != nil {
		t.Fatal(err)
	}
	db := f.raw(t)
	for _, q := range []string{`DELETE FROM events WHERE seq > 6`, `DELETE FROM checkpoints WHERE seq > 6`} {
		if _, err := db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	if rep := f.verify(t, true); !rep.OK() {
		t.Fatalf("rolled-back log should verify on its own (known limit): %v", rep.Problems)
	}
	pub, _ := LoadPublicKey(f.pubKey)
	rep, err := Verify(t.Context(), db, VerifyOptions{PublicKey: pub, Expect: []Anchor{anchor}})
	if err != nil {
		t.Fatal(err)
	}
	mustFail(t, rep, "rollback")

	bad := anchor
	bad.Seq = 3
	rep, _ = Verify(t.Context(), db, VerifyOptions{PublicKey: pub, Expect: []Anchor{bad}})
	mustFail(t, rep, "rewritten")
}

func TestParseAnchor(t *testing.T) {
	good := "12:" + strings.Repeat("ab", 32)
	if a, err := ParseAnchor(good); err != nil || a.Seq != 12 || a.String() != good {
		t.Fatalf("ParseAnchor(%q) = %+v, %v", good, a, err)
	}
	for _, s := range []string{"", "12", "x:" + strings.Repeat("ab", 32), "0:" + strings.Repeat("ab", 32), "1:zz", "1:" + strings.Repeat("zz", 32)} {
		if _, err := ParseAnchor(s); err == nil {
			t.Errorf("ParseAnchor(%q) accepted", s)
		}
	}
}
