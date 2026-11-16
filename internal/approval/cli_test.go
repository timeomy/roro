package approval

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/timeomy/tollgate/internal/store"
)

func newApprover(t *testing.T) (*CLIApprover, func(id string, approve bool) error) {
	t.Helper()
	db, err := store.Open(t.Context(), filepath.Join(t.TempDir(), "state.db"), Schema...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	a := NewCLIApprover(db)
	a.poll = 10 * time.Millisecond
	decide := func(id string, approve bool) error { return Decide(context.Background(), db, id, approve, "tester") }
	return a, decide
}

func request(id string, ttl time.Duration) Request {
	now := time.Now()
	return Request{ID: id, Agent: "a", Server: "s", Tool: "http.request", ArgsJSON: `{"url":"https://x"}`,
		Reason: "http_host_not_allowlisted", Created: now, Expires: now.Add(ttl)}
}

func TestTimeoutDenies(t *testing.T) {
	a, _ := newApprover(t)
	start := time.Now()
	res, err := a.RequestApproval(t.Context(), request("t1", 80*time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	if res.Approved() || res.Status != StatusExpired {
		t.Fatalf("result = %+v, want expired", res)
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("timeout took far too long")
	}
}

func TestHumanApproveAndDeny(t *testing.T) {
	for _, approve := range []bool{true, false} {
		a, decide := newApprover(t)
		go func() {
			for {
				if err := decide("x", approve); err == nil {
					return
				}
				time.Sleep(5 * time.Millisecond)
			}
		}()
		res, err := a.RequestApproval(t.Context(), request("x", 5*time.Second))
		if err != nil {
			t.Fatal(err)
		}
		if res.Approved() != approve || res.DecidedBy != "tester" {
			t.Fatalf("approve=%v: result = %+v", approve, res)
		}
	}
}

func TestCancellationStopsWait(t *testing.T) {
	a, decide := newApprover(t)
	ctx, cancel := context.WithCancel(t.Context())
	go func() { time.Sleep(30 * time.Millisecond); cancel() }()
	res, err := a.RequestApproval(ctx, request("c", time.Minute))
	if !errors.Is(err, context.Canceled) || res.Status != StatusCancelled {
		t.Fatalf("result = %+v, %v; want cancelled", res, err)
	}
	if err := decide("c", true); err == nil {
		t.Fatal("approving a cancelled request succeeded")
	}
}

func TestDecideRejectsUnknownAndExpired(t *testing.T) {
	a, decide := newApprover(t)
	if err := decide("nope", true); err == nil {
		t.Fatal("Decide on unknown id succeeded")
	}
	if _, err := a.RequestApproval(t.Context(), request("e", 30*time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if err := decide("e", true); err == nil {
		t.Fatal("Decide on expired request succeeded")
	}
}

func TestPendingListsRawArgs(t *testing.T) {
	a, decide := newApprover(t)
	go func() { _, _ = a.RequestApproval(context.Background(), request("p", 5*time.Second)) }()
	var got []Request
	for range 100 {
		got, _ = Pending(t.Context(), a.db)
		if len(got) == 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if len(got) != 1 || got[0].Tool != "http.request" || got[0].ArgsJSON != `{"url":"https://x"}` {
		t.Fatalf("Pending = %+v", got)
	}
	_ = decide("p", false)
}
