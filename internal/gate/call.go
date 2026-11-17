package gate

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"

	"github.com/timeomy/tollgate/internal/approval"
	"github.com/timeomy/tollgate/internal/audit"
	"github.com/timeomy/tollgate/internal/config"
	"github.com/timeomy/tollgate/internal/observe"
	"github.com/timeomy/tollgate/internal/pin"
	"github.com/timeomy/tollgate/internal/policy"
	"github.com/timeomy/tollgate/internal/redact"
)

// previewLimit bounds the redacted argument preview stored in the log.
const previewLimit = 512

// call is a parsed tools/call request.
type call struct {
	req      *jsonrpc.Request
	tool     string
	args     map[string]any
	redacted []byte           // redacted arguments, canonical JSON
	forward  *jsonrpc.Request // the request to send upstream if allowed
}

// verdict is the final decision for a call.
type verdict struct {
	outcome    policy.Outcome // Allow or Deny only
	reason     string
	policyIDs  []string
	approvalID string
	detail     string
}

type pendingCall struct {
	start time.Time
	span  *observe.CallSpan
	tool  string
	id    string
}

func (s *Session) handleCall(ctx context.Context, req *jsonrpc.Request) (jsonrpc.Message, jsonrpc.Message) {
	c, err := parseCall(req)
	ctx, span := s.deps.Telemetry.StartToolCall(ctx, observe.CallInfo{
		Tool: c.tool, Agent: s.info.Agent.Name, Server: s.info.Server,
		RequestID: idString(req.ID), Transport: s.info.Transport, SessionID: s.info.SessionID,
	})
	if err != nil {
		v := verdict{outcome: policy.Deny, reason: policy.ReasonMalformedRequest, detail: err.Error()}
		s.record(ctx, c, v)
		span.Decide(ctx, string(v.outcome), v.reason, nil, "")
		span.End(ctx, "tollgate."+v.reason, v.detail)
		return nil, invalidParams(req.ID, err.Error())
	}

	v := s.decide(ctx, c)
	if v.outcome == policy.Allow {
		if err := s.record(ctx, c, v); err != nil {
			v = verdict{outcome: policy.Deny, reason: policy.ReasonAuditUnavailable,
				detail: "the audit log could not record this call, so it was not forwarded"}
		}
	} else {
		_ = s.record(ctx, c, v)
	}
	span.Decide(ctx, string(v.outcome), v.reason, v.policyIDs, v.approvalID)

	if v.outcome != policy.Allow {
		span.End(ctx, "tollgate."+v.reason, v.detail)
		s.log.Info("tool call denied", "tool", c.tool, "reason", v.reason, "policies", v.policyIDs)
		return nil, denial(req.ID, c.tool, s.info.Agent.Name, v)
	}

	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		span.End(ctx, "tollgate.session_closed", "session closed")
		return nil, nil
	}
	s.calls[idKey(req.ID)] = &pendingCall{start: s.deps.Now(), span: span, tool: c.tool, id: idString(req.ID)}
	s.mu.Unlock()
	s.log.Debug("tool call allowed", "tool", c.tool, "reason", v.reason)
	return c.forward, nil
}

func parseCall(req *jsonrpc.Request) (call, error) {
	c := call{req: req, args: map[string]any{}, redacted: []byte("{}")}
	members, err := canonicalParams(req.Params)
	if err != nil {
		return c, fmt.Errorf("tools/call params rejected: %w", err)
	}
	if err := json.Unmarshal(members["name"], &c.tool); err != nil || c.tool == "" {
		c.tool = ""
		return c, errors.New("tools/call params.name is required and must be a string")
	}
	if !toolNamePattern.MatchString(c.tool) {
		name := c.tool
		c.tool = ""
		return c, fmt.Errorf("tools/call params.name %q is not a valid tool name (1-128 of A-Z a-z 0-9 . _ : / -)", truncate(name, 64))
	}
	if raw := bytes.TrimSpace(members["arguments"]); len(raw) > 0 && !bytes.Equal(raw, []byte("null")) {
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.UseNumber()
		if err := dec.Decode(&c.args); err != nil || c.args == nil {
			c.args = map[string]any{}
			return c, errors.New("tools/call params.arguments must be an object")
		}
	}
	red, err := json.Marshal(redact.Value(c.args))
	if err != nil {
		return c, errors.New("tools/call arguments could not be encoded")
	}
	c.redacted = red
	// Forward params re-encoded from the members the gate decided on, never
	// the bytes as received.
	params, err := json.Marshal(members)
	if err != nil {
		return c, errors.New("tools/call params could not be encoded")
	}
	c.forward = &jsonrpc.Request{ID: req.ID, Method: req.Method, Params: params}
	return c, nil
}

// decide runs the pipeline. Order matters: the kill switch and pinning are
// checked before policy so no policy can override them.
func (s *Session) decide(ctx context.Context, c call) verdict {
	agent := s.info.Agent.Name
	now := s.deps.Now()

	pinStatus, block := s.precheck(ctx, c)
	if block != nil {
		return *block
	}

	agentRate, toolRate := s.deps.Rates.Record(agent, c.tool, now)
	d := s.deps.Policy.Decide(policy.Request{
		Agent: s.info.Agent, Server: s.info.Server, Tool: c.tool, Args: c.args,
		Context: policy.Context{
			Now: now, KillSwitch: false, PinStatus: pinStatus,
			AgentCallsPerMinute: agentRate, ToolCallsPerMinute: toolRate,
			Matches: policy.EvaluateMatchers(s.deps.Matchers, c.args),
		},
	})
	v := verdict{outcome: d.Outcome, reason: d.Reason, policyIDs: d.PolicyIDs, detail: redact.String(d.Detail)}

	if s.deps.Mode == config.ModeMonitor && d.Outcome != policy.Allow {
		s.log.Warn("monitor mode: policy would not allow this call", "tool", c.tool, "outcome", d.Outcome, "reason", d.Reason)
		return verdict{outcome: policy.Allow, reason: "monitor:" + d.Reason, policyIDs: d.PolicyIDs,
			detail: "monitor mode; policy outcome was " + string(d.Outcome)}
	}
	if d.Outcome == policy.RequireApproval {
		v = s.askHuman(ctx, c, d)
		if v.outcome == policy.Allow {
			// The wait can last minutes: re-check the controls a human
			// approval must not override.
			if _, block := s.precheck(ctx, c); block != nil {
				block.approvalID, block.policyIDs = v.approvalID, v.policyIDs
				block.detail += " (after approval)"
				return *block
			}
		}
	}
	return v
}

// precheck runs the kill switch and pin checks. It returns the tool's pin
// status, and a non-nil verdict when the call must be denied.
func (s *Session) precheck(ctx context.Context, c call) (string, *verdict) {
	ks, err := s.deps.Kill.Check(ctx, s.info.Agent.Name)
	if err != nil {
		s.log.Error("kill switch state unreadable; denying", "err", err)
		return "", &verdict{outcome: policy.Deny, reason: policy.ReasonStateUnavailable, detail: "kill switch state unreadable"}
	}
	if ks.Active {
		return "", &verdict{outcome: policy.Deny, reason: policy.ReasonKillSwitch, detail: "kill switch active for " + ks.Scope}
	}
	pinStatus, err := s.deps.Pins.Status(ctx, s.info.Server, c.tool)
	if err != nil {
		s.log.Error("pin state unreadable", "err", err)
	}
	if pinStatus == pin.StatusChanged && s.deps.PinOnChange == config.PinBlock && s.deps.Mode == config.ModeEnforce {
		return pinStatus, &verdict{outcome: policy.Deny, reason: policy.ReasonToolChanged,
			detail: "tool definition changed since it was pinned; review with `tollgate pins list`"}
	}
	return pinStatus, nil
}

func (s *Session) askHuman(ctx context.Context, c call, d policy.Decision) verdict {
	if !s.deps.ApprovalSlots.tryAcquire() {
		return verdict{outcome: policy.Deny, reason: policy.ReasonApprovalError, policyIDs: d.PolicyIDs,
			detail: "too many calls are already waiting for approval"}
	}
	defer s.deps.ApprovalSlots.release()
	id := approval.NewID()
	key := idKey(c.req.ID)
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	s.mu.Lock()
	s.cancels[key] = cancel
	s.mu.Unlock()
	if s.wasCancelled(c.req.ID) {
		cancel()
	}
	defer func() {
		s.mu.Lock()
		delete(s.cancels, key)
		s.mu.Unlock()
	}()

	var pretty bytes.Buffer
	_ = json.Indent(&pretty, c.redacted, "", "  ")
	now := s.deps.Now()
	s.log.Info("waiting for human approval", "tool", c.tool, "approval_id", id, "timeout", s.deps.ApprovalTimeout)
	res, err := s.deps.Approver.RequestApproval(ctx, approval.Request{
		ID: id, Agent: s.info.Agent.Name, Server: s.info.Server, Tool: c.tool,
		ArgsJSON: pretty.String(), Reason: d.Reason, PolicyIDs: d.PolicyIDs,
		Created: now, Expires: now.Add(s.deps.ApprovalTimeout),
	})
	v := verdict{outcome: policy.Deny, policyIDs: d.PolicyIDs, approvalID: id}
	switch {
	case ctx.Err() != nil || s.wasCancelled(c.req.ID):
		v.reason, v.detail = policy.ReasonApprovalCancelled, "approval wait cancelled"
	case err != nil:
		v.reason, v.detail = policy.ReasonApprovalError, redact.String(err.Error())
	case res.Approved():
		v.outcome, v.reason, v.detail = policy.Allow, policy.ReasonApproved, "approved by "+res.DecidedBy
	case res.Status == approval.StatusExpired:
		v.reason, v.detail = policy.ReasonApprovalTimeout, "no decision before "+s.deps.ApprovalTimeout.String()
	default:
		v.reason, v.detail = policy.ReasonApprovalDenied, "denied by "+res.DecidedBy
	}
	return v
}

func (s *Session) cancelApproval(req *jsonrpc.Request) {
	var p struct {
		RequestID any `json:"requestId"`
	}
	if json.Unmarshal(req.Params, &p) != nil || p.RequestID == nil {
		return
	}
	id, err := jsonrpc.MakeID(p.RequestID)
	if err != nil {
		return
	}
	key := idKey(id)
	s.mu.Lock()
	cancel := s.cancels[key]
	if r := s.inflight[key]; r != nil {
		// Remember the cancel even if the approval wait has not started yet,
		// so a cancel that races ahead of it is not lost.
		r.cancelled = true
	}
	s.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}

// wasCancelled reports whether the client cancelled request id.
func (s *Session) wasCancelled(id jsonrpc.ID) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	r := s.inflight[idKey(id)]
	return r != nil && r.cancelled
}

// record appends the decision to the audit log.
func (s *Session) record(ctx context.Context, c call, v verdict) error {
	sum := sha256.Sum256(c.redacted)
	_, err := s.deps.Audit.Append(context.WithoutCancel(ctx), audit.Event{
		Kind: audit.KindToolCall, Agent: s.info.Agent.Name, Server: s.info.Server, Tool: c.tool,
		CallID: idString(c.req.ID), Session: s.info.SessionID,
		ArgsHash: hex.EncodeToString(sum[:]), ArgsPreview: truncate(string(c.redacted), previewLimit),
		Decision: string(v.outcome), Reason: v.reason, PolicyIDs: strings.Join(v.policyIDs, ","),
		ApprovalID: v.approvalID, Detail: v.detail,
	})
	if err != nil {
		s.log.Error("audit append failed", "err", err, "tool", c.tool)
	}
	return err
}

// finishCall records the upstream's answer to an allowed call.
func (s *Session) finishCall(ctx context.Context, pc *pendingCall, resp *jsonrpc.Response) {
	latency := s.deps.Now().Sub(pc.start)
	sum := sha256.Sum256(resp.Result)
	outcome, errType := "ok", ""
	if resp.Error != nil {
		outcome, errType = "rpc_error", "jsonrpc_error"
	} else {
		var r struct {
			IsError bool `json:"isError"`
		}
		if json.Unmarshal(resp.Result, &r) == nil && r.IsError {
			outcome, errType = observe.ErrorTypeToolError, observe.ErrorTypeToolError
		}
	}
	_, err := s.deps.Audit.Append(context.WithoutCancel(ctx), audit.Event{
		Kind: audit.KindToolResult, Agent: s.info.Agent.Name, Server: s.info.Server, Tool: pc.tool,
		CallID: pc.id, Session: s.info.SessionID, Reason: outcome,
		LatencyMS: latency.Milliseconds(), ResultDigest: hex.EncodeToString(sum[:]),
	})
	if err != nil {
		s.log.Error("audit append failed for tool result", "err", err, "tool", pc.tool)
	}
	pc.span.End(ctx, errType, outcome)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	cut := n
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "…"
}
