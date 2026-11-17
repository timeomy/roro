package gate

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"

	"github.com/timeomy/roro/internal/approval"
	"github.com/timeomy/roro/internal/audit"
	"github.com/timeomy/roro/internal/config"
	"github.com/timeomy/roro/internal/identity"
	"github.com/timeomy/roro/internal/killswitch"
	"github.com/timeomy/roro/internal/observe"
	"github.com/timeomy/roro/internal/pin"
	"github.com/timeomy/roro/internal/policy"
	"github.com/timeomy/roro/internal/store"
)

type env struct {
	t        *testing.T
	sess     *Session
	deps     Deps
	auditLog *audit.HashChainSQLiteLog
	auditDB  string
	pubKey   string
	kill     *killswitch.Switch
	spans    *tracetest.SpanRecorder
	approve  func(context.Context, approval.Request) (approval.Result, error)
}

func newEnv(t *testing.T, mutate ...func(*Deps)) *env {
	t.Helper()
	dir := t.TempDir()
	ctx := t.Context()

	keyPath := filepath.Join(dir, "k.key")
	if _, err := audit.GenerateKey(keyPath); err != nil {
		t.Fatal(err)
	}
	signer, err := audit.LoadSigner(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	e := &env{t: t, auditDB: filepath.Join(dir, "audit.db"), pubKey: keyPath + ".pub"}
	e.auditLog, err = audit.OpenLog(ctx, audit.Options{Path: e.auditDB, Signer: signer, CheckpointEvery: 1000})
	if err != nil {
		t.Fatal(err)
	}
	stateDB, err := store.Open(ctx, filepath.Join(dir, "state.db"), append(append(killswitch.Schema, pin.Schema...), approval.Schema...)...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stateDB.Close() })

	m1, _ := policy.NewMatcher("aws_access_key", `\b(AKIA|ASIA)[0-9A-Z]{16}\b`)
	m2, _ := policy.NewMatcher("private_key_block", `-----BEGIN [A-Z ]*PRIVATE KEY-----`)
	matchers := []policy.Matcher{m1, m2}
	engine, err := policy.LoadCedar([]string{"../../policies/examples/roro.cedar"}, policy.MatcherNames(matchers))
	if err != nil {
		t.Fatal(err)
	}

	e.spans = tracetest.NewSpanRecorder()
	tel := observe.New(sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(e.spans)), sdkmetric.NewMeterProvider(), nil)
	e.kill = killswitch.New(stateDB)
	e.approve = func(context.Context, approval.Request) (approval.Result, error) {
		return approval.Result{Status: approval.StatusExpired}, nil
	}
	e.deps = Deps{
		Policy: engine, Matchers: matchers, Rates: policy.NewRateCounter(), Audit: e.auditLog,
		Kill: e.kill, Pins: pin.New(stateDB),
		Approver:  approval.Func(func(ctx context.Context, r approval.Request) (approval.Result, error) { return e.approve(ctx, r) }),
		Telemetry: tel, Mode: config.ModeEnforce, PinOnChange: config.PinBlock, ApprovalTimeout: time.Second,
	}
	for _, m := range mutate {
		m(&e.deps)
	}
	e.sess, err = NewSession(e.deps, SessionInfo{
		Agent: identity.Agent{Name: "research-bot"}, Server: "demo", Transport: observe.TransportPipe, SessionID: "s1",
	})
	if err != nil {
		t.Fatal(err)
	}
	return e
}

var nextID int64

func toolCall(t *testing.T, tool string, args any) *jsonrpc.Request {
	t.Helper()
	nextID++
	id, _ := jsonrpc.MakeID(float64(nextID))
	p, err := json.Marshal(map[string]any{"name": tool, "arguments": args})
	if err != nil {
		t.Fatal(err)
	}
	return &jsonrpc.Request{ID: id, Method: "tools/call", Params: p}
}

// call runs a tools/call through the session. It returns forwarded=true if
// the request went upstream, else the decision metadata from the denial.
func (e *env) call(tool string, args any) (forwarded bool, meta DecisionMeta, req *jsonrpc.Request) {
	e.t.Helper()
	req = toolCall(e.t, tool, args)
	up, down := e.sess.FromClient(e.t.Context(), req)
	if up != nil {
		return true, DecisionMeta{}, req
	}
	resp, ok := down.(*jsonrpc.Response)
	if !ok {
		e.t.Fatalf("no upstream message and no client response for %s", tool)
	}
	if resp.Error != nil {
		return false, DecisionMeta{Reason: "jsonrpc_error:" + resp.Error.Error()}, req
	}
	var r struct {
		IsError bool                    `json:"isError"`
		Meta    map[string]DecisionMeta `json:"_meta"`
	}
	if err := json.Unmarshal(resp.Result, &r); err != nil || !r.IsError {
		e.t.Fatalf("denial is not an isError tool result: %s", resp.Result)
	}
	return false, r.Meta[MetaKey], req
}

func (e *env) events(f audit.Filter) []audit.Event {
	e.t.Helper()
	db, err := store.OpenExisting(e.t.Context(), e.auditDB)
	if err != nil {
		e.t.Fatal(err)
	}
	defer db.Close()
	evs, err := audit.Query(e.t.Context(), db, f)
	if err != nil {
		e.t.Fatal(err)
	}
	return evs
}

func (e *env) verifyLog() audit.Report {
	e.t.Helper()
	if err := e.auditLog.Checkpoint(e.t.Context()); err != nil {
		e.t.Fatal(err)
	}
	pub, err := audit.LoadPublicKey(e.pubKey)
	if err != nil {
		e.t.Fatal(err)
	}
	db, err := store.OpenExisting(e.t.Context(), e.auditDB)
	if err != nil {
		e.t.Fatal(err)
	}
	defer db.Close()
	rep, err := audit.Verify(e.t.Context(), db, audit.VerifyOptions{PublicKey: pub})
	if err != nil {
		e.t.Fatal(err)
	}
	return rep
}

// failingLog is an audit log that always fails.
type failingLog struct{}

func (failingLog) Append(context.Context, audit.Event) (audit.Event, error) {
	return audit.Event{}, errors.New("disk full")
}
func (failingLog) Checkpoint(context.Context) error { return nil }
func (failingLog) Close() error                     { return nil }
