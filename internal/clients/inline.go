package clients

import (
	"regexp"
	"strings"
)

// tomlInlineKey matches env = { ... } and http_headers = { ... } lines.
var tomlInlineKey = regexp.MustCompile(`^\s*(env|http_headers)\s*=\s*(.*)$`)

// tomlInline holds what one server wrote as inline tables.
type tomlInline struct {
	env, headers map[string]string
	unusual      bool
}

// tomlInlineTables reads `env = { K = "v" }` and `http_headers = { ... }`
// written directly inside [mcp_servers.NAME]. A table it cannot read in
// full (nested, not strings, or over several lines) marks the server
// unusual instead of being guessed at.
func tomlInlineTables(lines []string) map[string]*tomlInline {
	out := map[string]*tomlInline{}
	cur := ""
	for _, raw := range lines {
		line := strings.TrimSuffix(raw, "\r")
		if tomlAnyHeader.MatchString(line) {
			cur = ""
			if m := tomlHeader.FindStringSubmatch(line); m != nil {
				if s := tomlServer.FindStringSubmatch(tomlDotSpaces.ReplaceAllString(m[1], ".")); s != nil {
					cur = s[1] + s[2]
				}
			}
			continue
		}
		m := tomlInlineKey.FindStringSubmatch(line)
		if cur == "" || m == nil {
			continue
		}
		in := out[cur]
		if in == nil {
			in = &tomlInline{}
			out[cur] = in
		}
		value, _ := splitTOMLComment(m[2])
		table, ok := parseTOMLInlineTable(value)
		if !ok {
			in.unusual = true
			continue
		}
		if m[1] == "env" {
			in.env = mergeStrings(in.env, table)
		} else {
			in.headers = mergeStrings(in.headers, table)
		}
	}
	return out
}

func mergeStrings(a, b map[string]string) map[string]string {
	if len(a)+len(b) == 0 {
		return nil
	}
	out := make(map[string]string, len(a)+len(b))
	for k, v := range a {
		out[k] = v
	}
	for k, v := range b {
		out[k] = v
	}
	return out
}

// parseTOMLInlineTable reads a single-line { key = "string", ... } table.
func parseTOMLInlineTable(v string) (map[string]string, bool) {
	if len(v) < 2 || v[0] != '{' || v[len(v)-1] != '}' {
		return nil, false
	}
	out := map[string]string{}
	rest := strings.TrimSpace(v[1 : len(v)-1])
	for rest != "" {
		var key string
		if rest[0] == '"' || rest[0] == '\'' {
			end := tomlStringEnd(rest)
			if end < 0 {
				return nil, false
			}
			k, ok := parseTOMLString(rest[:end])
			if !ok {
				return nil, false
			}
			key, rest = k, strings.TrimSpace(rest[end:])
		} else {
			i := strings.IndexByte(rest, '=')
			if i < 0 {
				return nil, false
			}
			key, rest = strings.TrimSpace(rest[:i]), rest[i:]
		}
		if key == "" || rest == "" || rest[0] != '=' {
			return nil, false
		}
		rest = strings.TrimSpace(rest[1:])
		end := tomlStringEnd(rest)
		if end < 0 {
			return nil, false
		}
		val, ok := parseTOMLString(rest[:end])
		if !ok {
			return nil, false
		}
		out[key] = val
		rest = strings.TrimSpace(rest[end:])
		if rest == "" {
			break
		}
		if rest[0] != ',' {
			return nil, false
		}
		rest = strings.TrimSpace(rest[1:])
	}
	return out, true
}
