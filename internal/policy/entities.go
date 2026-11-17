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
//	principal  Roro::Agent::"<agent>"    {name, client, owner}
//	action     Roro::Action::"call_tool"
//	resource   Roro::Tool::"<tool>"      {name, server, args, paths, hosts}
//	context    {now, kill_switch, pin_status, rate{...}, matches{...}}
const (
	EntityAgent  = "Roro::Agent"
	EntityAction = "Roro::Action"
	EntityTool   = "Roro::Tool"
	ActionCall   = "call_tool"
)

func buildRequest(r Request, matcherNames []string) (cedar.Request, cedar.EntityMap, error) {
	if r.Agent.Name == "" || r.Tool == "" {
		return cedar.Request{}, nil, fmt.Errorf("policy: request needs an agent and a tool")
	}
	principal := cedar.NewEntityUID(EntityAgent, cedar.String(r.Agent.Name))
	action := cedar.NewEntityUID(EntityAction, ActionCall)
	resource := cedar.NewEntityUID(EntityTool, cedar.String(r.Tool))

	argsRec := cedar.NewRecord(nil)
	if r.Args != nil {
		args, err := toCedar(r.Args)
		if err != nil {
			return cedar.Request{}, nil, fmt.Errorf("policy: argument %w", err)
		}
		argsRec = args.(cedar.Record)
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

// maxLongPlusOne is 2^63, the first float64 above Cedar's Long range.
const maxLongPlusOne = 9223372036854775808.0

// toCedar converts a decoded JSON value to a Cedar value. A number Cedar
// cannot represent (outside the Long range and not a representable decimal,
// NaN, infinities) is an error, never dropped: a dropped argument would make
// `resource.args has x` false and let a bounded argument through unchecked.
// The caller denies on error.
//
// JSON null is the one value that is dropped: Cedar has no null, and MCP
// servers treat a null optional argument as absent, which is what policy
// sees (`has` is false). Policies that bound an argument must therefore
// either require it (`resource.args has limit && ...`) or accept that an
// absent or null argument means the server's default.
func toCedar(v any) (cedar.Value, error) {
	switch t := v.(type) {
	case string:
		return cedar.String(t), nil
	case bool:
		return cedar.Boolean(t), nil
	case json.Number:
		if i, err := t.Int64(); err == nil {
			return cedar.Long(i), nil
		}
		f, err := t.Float64()
		if err != nil {
			return nil, fmt.Errorf("number %s is out of range", truncateNum(t.String()))
		}
		return floatToCedar(f)
	case float64:
		return floatToCedar(t)
	case int:
		return cedar.Long(t), nil
	case int64:
		return cedar.Long(t), nil
	case []any:
		vals := make([]cedar.Value, 0, len(t))
		for _, e := range t {
			if e == nil {
				continue
			}
			cv, err := toCedar(e)
			if err != nil {
				return nil, err
			}
			vals = append(vals, cv)
		}
		return cedar.NewSet(vals...), nil
	case map[string]any:
		rm := make(cedar.RecordMap, len(t))
		for k, e := range t {
			if e == nil {
				continue
			}
			cv, err := toCedar(e)
			if err != nil {
				return nil, fmt.Errorf("%q: %w", truncateNum(k), err)
			}
			rm[cedar.String(k)] = cv
		}
		return cedar.NewRecord(rm), nil
	case nil:
		return nil, fmt.Errorf("value is null, which policy cannot evaluate")
	default:
		return nil, fmt.Errorf("value of type %T cannot be evaluated", v)
	}
}

func floatToCedar(f float64) (cedar.Value, error) {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return nil, fmt.Errorf("number is out of range")
	}
	// Compare against 2^63 exactly: float64(math.MaxInt64) rounds up to 2^63,
	// and int64(2^63) overflows.
	if f == math.Trunc(f) && f >= math.MinInt64 && f < maxLongPlusOne {
		return cedar.Long(int64(f)), nil
	}
	d, err := cedar.NewDecimalFromFloat(f)
	if err != nil {
		return nil, fmt.Errorf("number %g is out of range", f)
	}
	return d, nil
}

func truncateNum(s string) string {
	if len(s) > 32 {
		return s[:32] + "..."
	}
	return s
}

// derivedPaths exposes cleaned forms of top-level string arguments that look
// like filesystem paths. Cleaning resolves "." and ".." lexically, so
// "/sandbox/../etc/passwd" becomes "/etc/passwd" and cannot satisfy
// `like "/sandbox/*"`. Symlinks are not resolved (Roro does not see the
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
