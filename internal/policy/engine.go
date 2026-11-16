// Package policy decides whether a tool call is allowed, denied, or needs
// human approval.
//
// The Engine interface keeps the rest of Tollgate independent of the policy
// language. v0.1 ships a Cedar implementation (CedarEngine).
package policy

import (
	"time"

	"github.com/timeomy/tollgate/internal/identity"
)

// Outcome is the result of a policy decision.
type Outcome string

// Decision outcomes.
const (
	Allow           Outcome = "allow"
	Deny            Outcome = "deny"
	RequireApproval Outcome = "require_approval"
)

// Stable, machine-readable reason codes produced by Tollgate itself. Policy
// authors add their own with the @reason("...") annotation.
const (
	ReasonPermitted         = "permitted"
	ReasonNoMatchingPermit  = "no_matching_permit"
	ReasonForbidden         = "forbidden_by_policy"
	ReasonApprovalRequired  = "approval_required"
	ReasonEvaluationError   = "policy_evaluation_error"
	ReasonKillSwitch        = "kill_switch_active"
	ReasonToolChanged       = "tool_definition_changed"
	ReasonApprovalTimeout   = "approval_timeout"
	ReasonApprovalDenied    = "approval_denied"
	ReasonApproved          = "approved_by_human"
	ReasonApprovalCancelled = "approval_cancelled"
	ReasonApprovalError     = "approval_unavailable"
	ReasonAuditUnavailable  = "audit_unavailable"
	ReasonMalformedRequest  = "malformed_request"
	ReasonStateUnavailable  = "state_unavailable"
)

// Request is everything the engine may consider for one tool call.
type Request struct {
	Agent  identity.Agent
	Server string
	Tool   string
	// Args are the raw tool arguments as decoded from JSON (json.Number for
	// numbers). Policy sees raw values; only logs see redacted ones.
	Args    map[string]any
	Context Context
}

// Context carries runtime facts that are not part of the call itself.
type Context struct {
	Now                 time.Time
	KillSwitch          bool
	PinStatus           string
	AgentCallsPerMinute int
	ToolCallsPerMinute  int
	// Matches holds the result of every configured named matcher.
	Matches map[string]bool
}

// Decision is the engine's answer.
type Decision struct {
	Outcome Outcome
	// Reason is a stable machine-readable code.
	Reason string
	// PolicyIDs are the policies that determined the decision.
	PolicyIDs []string
	// Detail is a human-readable explanation (never contains argument values).
	Detail string
}

// Engine decides tool calls. Implementations must fail closed: any internal
// error yields Deny, never Allow.
type Engine interface {
	Decide(Request) Decision
}
