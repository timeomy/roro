package gate

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"

	"github.com/timeomy/tollgate/internal/audit"
	"github.com/timeomy/tollgate/internal/config"
	"github.com/timeomy/tollgate/internal/pin"
)

// handleListResult pins the tools in a tools/list response. In block mode
// (enforce), tools whose definition changed since pinning are removed from
// the listing, so the model never reads an unreviewed description.
func (s *Session) handleListResult(ctx context.Context, resp *jsonrpc.Response) jsonrpc.Message {
	if resp.Error != nil {
		return resp
	}
	var result map[string]json.RawMessage
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		return s.listFailure(resp, fmt.Errorf("tools/list result is not an object"))
	}
	var raws []json.RawMessage
	if err := json.Unmarshal(result["tools"], &raws); err != nil {
		return s.listFailure(resp, fmt.Errorf("tools/list result.tools is not an array"))
	}
	tools := make([]pin.Tool, 0, len(raws))
	for _, r := range raws {
		var t struct {
			Name string `json:"name"`
		}
		if json.Unmarshal(r, &t) != nil || t.Name == "" {
			return s.listFailure(resp, fmt.Errorf("tools/list contains a tool without a name"))
		}
		tools = append(tools, pin.Tool{Name: t.Name, Raw: r})
	}

	changes, err := s.deps.Pins.Observe(context.WithoutCancel(ctx), s.info.Server, tools)
	if err != nil {
		return s.listFailure(resp, err)
	}
	s.auditPinChanges(ctx, changes)

	if s.deps.PinOnChange != config.PinBlock || s.deps.Mode != config.ModeEnforce {
		return resp
	}
	kept := make([]json.RawMessage, 0, len(tools))
	hidden := 0
	for i, t := range tools {
		st, err := s.deps.Pins.Status(ctx, s.info.Server, t.Name)
		if err != nil || st == pin.StatusChanged {
			hidden++
			continue
		}
		kept = append(kept, raws[i])
	}
	if hidden == 0 {
		return resp
	}
	s.log.Warn("hid changed tools from tools/list", "hidden", hidden)
	newTools, _ := json.Marshal(kept)
	result["tools"] = newTools
	b, err := json.Marshal(result)
	if err != nil {
		return s.listFailure(resp, err)
	}
	return &jsonrpc.Response{ID: resp.ID, Result: b}
}

// listFailure fails closed in block mode (no tools are shown), and passes the
// original response through in alert/monitor mode.
func (s *Session) listFailure(resp *jsonrpc.Response, err error) jsonrpc.Message {
	s.log.Error("tool pinning failed", "err", err)
	if s.deps.PinOnChange == config.PinBlock && s.deps.Mode == config.ModeEnforce {
		return internalError(resp.ID, "tool pinning failed; tools/list withheld")
	}
	return resp
}

func (s *Session) auditPinChanges(ctx context.Context, changes []pin.Change) {
	for _, c := range changes {
		decision := ""
		if c.Kind == "changed" {
			decision = s.deps.PinOnChange
			s.log.Warn("tool definition changed since pinned", "tool", c.Tool, "action", decision,
				"old_hash", c.OldHash[:12], "new_hash", c.NewHash[:12])
		}
		_, err := s.deps.Audit.Append(context.WithoutCancel(ctx), audit.Event{
			Kind: audit.KindPinChange, Agent: s.info.Agent.Name, Server: c.Server, Tool: c.Tool,
			Session: s.info.SessionID, Decision: decision, Reason: "tool_" + c.Kind,
			Detail: fmt.Sprintf("old=%s new=%s", c.OldHash, c.NewHash),
		})
		if err != nil {
			s.log.Error("audit append failed for pin change", "err", err)
		}
	}
}
