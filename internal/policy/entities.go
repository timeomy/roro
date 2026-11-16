package policy

import (
	"encoding/json"
	"fmt"
	"math"
	"net/url"
	"path"
	"strings"

	"github.com/cedar-policy/cedar-go"
)

// Cedar entity model (see docs/policy.md):
//
//	principal  Tollgate::Agent::"<agent>"    {name, client, owner}
//	action     Tollgate::Action::"call_tool"
//	resource   Tollgate::Tool::"<tool>"      {name, server, args, paths, hosts}
//	context    {now, kill_switch, pin_status, rate{...}, matches{...}}
const (
	EntityAgent  = "Tollgate::Agent"
	EntityAction = "Tollgate::Action"
	EntityTool   = "Tollgate::Tool"
	ActionCall   = "call_tool"
)

func buildRequest(r Request, matcherNames []string) (cedar.Request, cedar.EntityMap, error) {
	if r.Agent.Name == "" || r.Tool == "" {
		return cedar.Request{}, nil, fmt.Errorf("policy: request needs an agent and a tool")
	}
	principal := cedar.NewEntityUID(EntityAgent, cedar.String(r.Agent.Name))
	action := cedar.NewEntityUID(EntityAction, ActionCall)
	resource := cedar.NewEntityUID(EntityTool, cedar.String(r.Tool))

	args, _ := toCedar(r.Args)
	argsRec, ok := args.(cedar.Record)
	if !ok {
		argsRec = cedar.NewRecord(nil)
	}
	entities := cedar.EntityMap{
		principal: {UID: principal, Attributes: cedar.NewRecord(cedar.RecordMap{
			"name":   cedar.String(r.Agent.Name),
			"client": cedar.String(r.Agent.Client),
			"owner":  cedar.String(r.Agent.Owner),
		})},
		action: {UID: action},
		resource: {UID: resource, Attributes: cedar.NewRecord(cedar.RecordMap{
			"name":   cedar.String(r.Tool),
			"server": cedar.String(r.Server),
			"args":   argsRec,
			"paths":  derivedPaths(r.Args),
			"hosts":  derivedHosts(r.Args),
		})},
	}

	matches := cedar.RecordMap{}
	for _, name := range matcherNames {
		matches[cedar.String(name)] = cedar.Boolean(r.Context.Matches[name])
	}
	ctx := cedar.NewRecord(cedar.RecordMap{
		"now":         cedar.Long(r.Context.Now.Unix()),
		"kill_switch": cedar.Boolean(r.Context.KillSwitch),
		"pin_status":  cedar.String(r.Context.PinStatus),
		"rate": cedar.NewRecord(cedar.RecordMap{
			"agent_calls_per_minute": cedar.Long(r.Context.AgentCallsPerMinute),
			"tool_calls_per_minute":  cedar.Long(r.Context.ToolCallsPerMinute),
		}),
		"matches": cedar.NewRecord(matches),
	})
	return cedar.Request{Principal: principal, Action: action, Resource: resource, Context: ctx}, entities, nil
}

// toCedar converts a decoded JSON value to a Cedar value. Nulls and values
// Cedar cannot represent are dropped (ok=false), so `has` checks in policy
// see them as absent.
func toCedar(v any) (cedar.Value, bool) {
	switch t := v.(type) {
	case string:
		return cedar.String(t), true
	case bool:
		return cedar.Boolean(t), true
	case json.Number:
		if i, err := t.Int64(); err == nil {
			return cedar.Long(i), true
		}
		f, err := t.Float64()
		if err != nil {
			return nil, false
		}
		return floatToCedar(f)
	case float64:
		return floatToCedar(t)
	case int:
		return cedar.Long(t), true
	case int64:
		return cedar.Long(t), true
	case []any:
		vals := make([]cedar.Value, 0, len(t))
		for _, e := range t {
			if cv, ok := toCedar(e); ok {
				vals = append(vals, cv)
			}
		}
		return cedar.NewSet(vals...), true
	case map[string]any:
		rm := make(cedar.RecordMap, len(t))
		for k, e := range t {
			if cv, ok := toCedar(e); ok {
				rm[cedar.String(k)] = cv
			}
		}
		return cedar.NewRecord(rm), true
	default:
		return nil, false
	}
}

func floatToCedar(f float64) (cedar.Value, bool) {
	if f == math.Trunc(f) && f >= math.MinInt64 && f <= math.MaxInt64 {
		return cedar.Long(int64(f)), true
	}
	d, err := cedar.NewDecimalFromFloat(f)
	if err != nil {
		return nil, false
	}
	return d, true
}

// derivedPaths exposes cleaned forms of top-level string arguments that look
// like filesystem paths. Cleaning resolves "." and ".." lexically, so
// "/sandbox/../etc/passwd" becomes "/etc/passwd" and cannot satisfy
// `like "/sandbox/*"`. Symlinks are not resolved (Tollgate does not see the
// upstream's filesystem); see docs/threat-model.md.
func derivedPaths(args map[string]any) cedar.Record {
	rm := cedar.RecordMap{}
	for k, v := range args {
		s, ok := v.(string)
		if !ok {
			continue
		}
		if p, ok := cleanPath(s); ok {
			rm[cedar.String(k)] = cedar.String(p)
		}
	}
	return cedar.NewRecord(rm)
}

func cleanPath(s string) (string, bool) {
	if strings.HasPrefix(s, "file://") {
		u, err := url.Parse(s)
		if err != nil || (u.Host != "" && u.Host != "localhost") {
			return "", false
		}
		s = u.Path
	}
	s = strings.ReplaceAll(s, `\`, "/")
	looksLikePath := strings.HasPrefix(s, "/") || strings.HasPrefix(s, "./") ||
		strings.HasPrefix(s, "../") || strings.HasPrefix(s, "~") ||
		(len(s) >= 3 && s[1] == ':' && s[2] == '/') // C:/...
	if !looksLikePath {
		return "", false
	}
	return path.Clean(s), true
}

// derivedHosts exposes the lowercase hostname of top-level string arguments
// that are absolute http(s)/ws(s) URLs.
func derivedHosts(args map[string]any) cedar.Record {
	rm := cedar.RecordMap{}
	for k, v := range args {
		s, ok := v.(string)
		if !ok {
			continue
		}
		u, err := url.Parse(strings.TrimSpace(s))
		if err != nil {
			continue
		}
		switch strings.ToLower(u.Scheme) {
		case "http", "https", "ws", "wss":
		default:
			continue
		}
		host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
		if host != "" {
			rm[cedar.String(k)] = cedar.String(host)
		}
	}
	return cedar.NewRecord(rm)
}
