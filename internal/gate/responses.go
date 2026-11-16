package gate

import (
	"encoding/json"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
)

// MetaKey is the _meta key carrying Tollgate's machine-readable decision on
// a blocked call.
const MetaKey = "io.github.timeomy.tollgate/decision"

// DecisionMeta is the value under MetaKey.
type DecisionMeta struct {
	Decision   string   `json:"decision"`
	Reason     string   `json:"reason"`
	PolicyIDs  []string `json:"policy_ids,omitempty"`
	ApprovalID string   `json:"approval_id,omitempty"`
}

// denial answers a blocked tools/call with a tool result whose isError is
// true. The model sees why it was blocked and can tell the user; the call
// never reaches the upstream server.
func denial(id jsonrpc.ID, tool, agent string, v verdict) *jsonrpc.Response {
	text := fmt.Sprintf("Tollgate blocked the call to tool %q for agent %q (reason: %s).", tool, agent, v.reason)
	if v.detail != "" {
		text += " " + v.detail + "."
	}
	result := map[string]any{
		"content": []any{map[string]any{"type": "text", "text": text}},
		"isError": true,
		"_meta": map[string]any{MetaKey: DecisionMeta{
			Decision: string(v.outcome), Reason: v.reason, PolicyIDs: v.policyIDs, ApprovalID: v.approvalID,
		}},
	}
	b, err := json.Marshal(result)
	if err != nil { // cannot happen with these types; fall back to a protocol error
		return &jsonrpc.Response{ID: id, Error: &jsonrpc.Error{Code: jsonrpc.CodeInternalError, Message: "tollgate: call blocked"}}
	}
	return &jsonrpc.Response{ID: id, Result: b}
}

func invalidParams(id jsonrpc.ID, msg string) *jsonrpc.Response {
	return &jsonrpc.Response{ID: id, Error: &jsonrpc.Error{Code: jsonrpc.CodeInvalidParams, Message: "tollgate: " + msg}}
}

func internalError(id jsonrpc.ID, msg string) *jsonrpc.Response {
	return &jsonrpc.Response{ID: id, Error: &jsonrpc.Error{Code: jsonrpc.CodeInternalError, Message: "tollgate: " + msg}}
}
