package policy

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/timeomy/tollgate/internal/identity"
)

const starterPolicy = "../../policies/examples/tollgate.cedar"

func starterEngine(t *testing.T) *CedarEngine {
	t.Helper()
	e, err := LoadCedar([]string{starterPolicy}, []string{"aws_access_key", "private_key_block"})
	if err != nil {
		t.Fatalf("LoadCedar: %v", err)
	}
	return e
}

func args(t *testing.T, raw string) map[string]any {
	t.Helper()
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.UseNumber()
	var m map[string]any
	if err := dec.Decode(&m); err != nil {
		t.Fatal(err)
	}
	return m
}

func req(tool, rawArgs string) Request {
	return Request{
		Agent:   identity.Agent{Name: "research-bot", Client: "test"},
		Server:  "demo",
		Tool:    tool,
		Context: Context{Now: time.Unix(1_800_000_000, 0), PinStatus: "pinned", AgentCallsPerMinute: 1, ToolCallsPerMinute: 1},
	}.withArgs(rawArgs)
}

func (r Request) withArgs(raw string) Request {
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.UseNumber()
	var m map[string]any
	_ = dec.Decode(&m)
	r.Args = m
	return r
}

func TestStarterPolicyDecisions(t *testing.T) {
	e := starterEngine(t)
	cases := []struct {
		name    string
		req     Request
		outcome Outcome
		reason  string
	}{
		{"read inside sandbox", req("read_file", `{"path":"/sandbox/notes.txt"}`), Allow, ReasonPermitted},
		{"read outside sandbox", req("read_file", `{"path":"/etc/passwd"}`), Deny, ReasonNoMatchingPermit},
		{"read traversal out of sandbox", req("read_file", `{"path":"/sandbox/../etc/passwd"}`), Deny, ReasonNoMatchingPermit},
		{"read sibling prefix", req("read_file", `{"path":"/sandbox-evil/x"}`), Deny, ReasonNoMatchingPermit},
		{"read relative path", req("read_file", `{"path":"notes.txt"}`), Deny, ReasonNoMatchingPermit},
		{"read missing path arg", req("read_file", `{}`), Deny, ReasonNoMatchingPermit},
		{"write inside sandbox", req("write_file", `{"path":"/sandbox/out.txt","content":"x"}`), Allow, ReasonPermitted},
		{"write outside sandbox", req("fs.write", `{"path":"/etc/cron.d/x"}`), Deny, "write_outside_sandbox"},
		{"http allowlisted host", req("http.request", `{"url":"https://api.github.com/repos"}`), Allow, ReasonPermitted},
		{"http host case/dot", req("http.request", `{"url":"https://API.GitHub.com./x"}`), Allow, ReasonPermitted},
		{"http other host", req("http.request", `{"url":"https://evil.example/collect"}`), RequireApproval, "http_host_not_allowlisted"},
		{"http userinfo trick", req("http.request", `{"url":"https://api.github.com@evil.example/"}`), RequireApproval, "http_host_not_allowlisted"},
		{"exfil tool", req("exfiltrate", `{"data":"x"}`), Deny, "dangerous_tool_blocked"},
		{"exec tool", req("exec", `{"cmd":"id"}`), Deny, "dangerous_tool_blocked"},
		{"send_email tool", req("send_email", `{"to":"a@b.c"}`), Deny, "dangerous_tool_blocked"},
		{"unknown tool", req("delete_repo", `{}`), Deny, ReasonNoMatchingPermit},
		{"numeric bound ok", req("search", `{"q":"x","limit":100}`), Allow, ReasonPermitted},
		{"numeric bound exceeded", req("search", `{"q":"x","limit":101}`), Deny, ReasonNoMatchingPermit},
		{"numeric bound above int64", req("search", `{"q":"x","limit":99999999999999999999}`), Deny, ReasonEvaluationError},
		{"numeric bound 1e400", req("search", `{"q":"x","limit":1e400}`), Deny, ReasonEvaluationError},
		{"numeric bound 1e19", req("search", `{"q":"x","limit":1e19}`), Deny, ReasonEvaluationError},
		{"numeric bound 2^63", req("search", `{"q":"x","limit":9223372036854775808}`), Deny, ReasonEvaluationError},
		{"numeric bound float 2^63", req("search", `{"q":"x","limit":9.223372036854775808e18}`), Deny, ReasonEvaluationError},
		{"numeric bound nested overflow", req("search", `{"q":"x","limit":5,"opts":[1e400]}`), Deny, ReasonEvaluationError},
		{"numeric bound float in range", req("search", `{"q":"x","limit":1e2}`), Allow, ReasonPermitted},
		{"numeric bound string", req("search", `{"q":"x","limit":"5000"}`), Deny, ReasonNoMatchingPermit},
		{"null optional arg is absent", req("search", `{"q":"x","limit":null}`), Allow, ReasonPermitted},
		{"echo", req("echo", `{"text":"hi"}`), Allow, ReasonPermitted},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := e.Decide(c.req)
			if d.Outcome != c.outcome || d.Reason != c.reason {
				t.Fatalf("Decide = %s/%s (%v), want %s/%s", d.Outcome, d.Reason, d.PolicyIDs, c.outcome, c.reason)
			}
		})
	}
}

func TestExceptionForNamedAgent(t *testing.T) {
	e := starterEngine(t)
	r := req("run_shell", `{"cmd":"uptime"}`)
	if d := e.Decide(r); d.Outcome != Deny {
		t.Fatalf("research-bot run_shell = %s, want deny", d.Outcome)
	}
	r.Agent.Name = "ops-bot"
	// The forbid no longer applies, but nothing permits run_shell either.
	if d := e.Decide(r); d.Outcome != Deny || d.Reason != ReasonNoMatchingPermit {
		t.Fatalf("ops-bot run_shell = %s/%s, want deny/no_matching_permit", d.Outcome, d.Reason)
	}
}

func TestContextRules(t *testing.T) {
	e := starterEngine(t)
	r := req("echo", `{"text":"hi"}`)

	r.Context.KillSwitch = true
	if d := e.Decide(r); d.Outcome != Deny || d.Reason != "kill_switch_active" {
		t.Errorf("kill switch: %s/%s", d.Outcome, d.Reason)
	}
	r.Context.KillSwitch = false

	r.Context.AgentCallsPerMinute = 31
	if d := e.Decide(r); d.Outcome != Deny || d.Reason != "rate_limit_exceeded" {
		t.Errorf("agent rate: %s/%s", d.Outcome, d.Reason)
	}
	r.Context.AgentCallsPerMinute = 1

	w := req("write_file", `{"path":"/sandbox/a"}`)
	w.Context.ToolCallsPerMinute = 6
	if d := e.Decide(w); d.Outcome != Deny || d.Reason != "rate_limit_exceeded" {
		t.Errorf("write-tool rate: %s/%s", d.Outcome, d.Reason)
	}

	s := req("echo", `{"text":"AKIAIOSFODNN7EXAMPLE"}`)
	s.Context.Matches = map[string]bool{"aws_access_key": true}
	if d := e.Decide(s); d.Outcome != Deny || d.Reason != "secret_in_arguments" {
		t.Errorf("secret matcher: %s/%s", d.Outcome, d.Reason)
	}
}

func TestMatchersFeedContext(t *testing.T) {
	m, err := NewMatcher("aws_access_key", `AKIA[0-9A-Z]{16}`)
	if err != nil {
		t.Fatal(err)
	}
	got := EvaluateMatchers([]Matcher{m}, args(t, `{"nested":{"list":["ok","key AKIAIOSFODNN7EXAMPLE"]}}`))
	if !got["aws_access_key"] {
		t.Error("matcher missed nested string")
	}
	if EvaluateMatchers([]Matcher{m}, args(t, `{"text":"clean"}`))["aws_access_key"] {
		t.Error("matcher matched clean input")
	}
	if _, err := NewMatcher("bad", "("); err == nil {
		t.Error("NewMatcher accepted an invalid regex")
	}
}

func writeCedar(t *testing.T, src string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "p.cedar")
	if err := os.WriteFile(p, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadFailsClosed(t *testing.T) {
	cases := map[string]string{
		"syntax error":       `permit (principal, action, resource) when { ;`,
		"empty file":         ``,
		"approval on forbid": `@approval forbid (principal, action, resource);`,
		"bad reason":         `@reason("Not Snake") forbid (principal, action, resource);`,
		"duplicate id":       `@id("a") permit (principal, action, resource); @id("a") permit (principal, action, resource);`,
	}
	for name, src := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := LoadCedar([]string{writeCedar(t, src)}, nil); err == nil {
				t.Fatal("LoadCedar accepted a bad policy")
			}
		})
	}
	if _, err := LoadCedar([]string{filepath.Join(t.TempDir(), "missing.cedar")}, nil); err == nil {
		t.Fatal("LoadCedar accepted a missing file")
	}
}

func TestErroringForbidFailsClosed(t *testing.T) {
	// The forbid reads an attribute that does not exist; Cedar skips erroring
	// policies, which would let the permit through. Tollgate must deny.
	p := writeCedar(t, `
permit (principal, action, resource);
@id("broken") forbid (principal, action, resource) when { resource.args.missing == "x" };
`)
	e, err := LoadCedar([]string{p}, nil)
	if err != nil {
		t.Fatal(err)
	}
	d := e.Decide(req("echo", `{}`))
	if d.Outcome != Deny || d.Reason != ReasonEvaluationError {
		t.Fatalf("Decide = %s/%s, want deny/%s", d.Outcome, d.Reason, ReasonEvaluationError)
	}
}

func TestEmptyAgentDenied(t *testing.T) {
	e := starterEngine(t)
	r := req("echo", `{}`)
	r.Agent.Name = ""
	if d := e.Decide(r); d.Outcome != Deny {
		t.Fatalf("Decide with no agent = %s, want deny", d.Outcome)
	}
}

func TestRateCounterSlidingWindow(t *testing.T) {
	c := NewRateCounter()
	t0 := time.Unix(1_800_000_000, 0)
	for i := range 3 {
		c.Record("a", "echo", t0.Add(time.Duration(i)*time.Second))
	}
	a, tool := c.Record("a", "other", t0.Add(3*time.Second))
	if a != 4 || tool != 1 {
		t.Fatalf("counts = %d/%d, want 4/1", a, tool)
	}
	a, tool = c.Record("a", "echo", t0.Add(RateWindow+2*time.Second))
	// Window is (t0+2s, t0+62s]: only the "other" call at t0+3s and this one remain.
	if a != 2 || tool != 1 {
		t.Fatalf("after window: counts = %d/%d, want 2/1", a, tool)
	}
	if b, _ := c.Record("b", "echo", t0); b != 1 {
		t.Fatalf("agents share counters: %d", b)
	}
}

func TestRateCounterSweepsStaleKeys(t *testing.T) {
	c := NewRateCounter()
	t0 := time.Unix(1_800_000_000, 0)
	for i := range 500 {
		c.Record("bot", fmt.Sprintf("made_up_%d", i), t0)
	}
	if c.keys() < 500 {
		t.Fatalf("keys = %d", c.keys())
	}
	c.Record("bot", "echo", t0.Add(2*RateWindow))
	if got := c.keys(); got != 2 { // the agent key and bot/echo
		t.Fatalf("after sweep keys = %d, want 2", got)
	}
}
