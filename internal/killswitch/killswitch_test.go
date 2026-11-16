package killswitch

import (
	"path/filepath"
	"testing"

	"github.com/timeomy/tollgate/internal/store"
)

func open(t *testing.T, path string) *Switch {
	t.Helper()
	db, err := store.Open(t.Context(), path, Schema...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return New(db)
}

func TestGlobalAndPerAgent(t *testing.T) {
	s := open(t, filepath.Join(t.TempDir(), "state.db"))
	ctx := t.Context()

	if st, _ := s.Check(ctx, "a"); st.Active {
		t.Fatal("fresh switch is active")
	}
	if err := s.Kill(ctx, "a", "suspicious", "test"); err != nil {
		t.Fatal(err)
	}
	if st, _ := s.Check(ctx, "a"); !st.Active || st.Scope != "agent:a" || st.Reason != "suspicious" {
		t.Fatalf("agent a status = %+v", st)
	}
	if st, _ := s.Check(ctx, "b"); st.Active {
		t.Fatal("killing agent a also killed agent b")
	}

	if err := s.Kill(ctx, "", "incident", "test"); err != nil {
		t.Fatal(err)
	}
	if st, _ := s.Check(ctx, "b"); !st.Active || st.Scope != GlobalScope {
		t.Fatalf("global kill not applied to b: %+v", st)
	}

	if err := s.Resume(ctx, "", "resolved", "test"); err != nil {
		t.Fatal(err)
	}
	if st, _ := s.Check(ctx, "b"); st.Active {
		t.Fatal("b still killed after global resume")
	}
	if st, _ := s.Check(ctx, "a"); !st.Active {
		t.Fatal("global resume cleared the per-agent kill for a")
	}
	if err := s.Resume(ctx, "a", "", "test"); err != nil {
		t.Fatal(err)
	}
	if st, _ := s.Check(ctx, "a"); st.Active {
		t.Fatal("a still killed after resume")
	}
}

func TestStatePersistsAcrossRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	db, err := store.Open(t.Context(), path, Schema...)
	if err != nil {
		t.Fatal(err)
	}
	if err := New(db).Kill(t.Context(), "", "persist me", "test"); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	// A new "process": reopen from disk.
	s := open(t, path)
	if st, _ := s.Check(t.Context(), "anyone"); !st.Active || st.Reason != "persist me" {
		t.Fatalf("after restart status = %+v", st)
	}
	entries, err := s.List(t.Context())
	if err != nil || len(entries) != 1 || !entries[0].Active {
		t.Fatalf("List = %+v, %v", entries, err)
	}
}

func TestUnreadableStateFailsClosed(t *testing.T) {
	db, err := store.Open(t.Context(), filepath.Join(t.TempDir(), "state.db")) // no schema
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	st, err := New(db).Check(t.Context(), "a")
	if err == nil || !st.Active {
		t.Fatalf("Check on broken state = %+v, %v; want active + error", st, err)
	}
}
