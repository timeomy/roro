package clients

import (
	"strings"
)

// Server is one MCP server entry as written in a client configuration.
// It is read-only: scanning never changes a file.
type Server struct {
	Name  string
	Scope string // empty for user-wide entries, else the project path

	Command string
	Args    []string
	Env     map[string]string // only string values; other types are ignored

	URL     string            // remote servers (url, serverUrl, httpUrl)
	Headers map[string]string // remote servers; only string values

	// Unusual is true when the entry is written in a form Roro does not
	// fully read, so checks on it may be incomplete.
	Unusual bool
}

// Remote reports whether the entry is a remote (HTTP) server.
func (s Server) Remote() bool { return s.Command == "" && s.URL != "" }

// ListServers returns every MCP server entry in a client configuration
// file, without running anything.
func ListServers(format Format, data []byte) ([]Server, error) {
	if format == FormatCodexTOML {
		return listTOML(data), nil
	}
	root, err := decodeJSON(data)
	if err != nil {
		return nil, err
	}
	var out []Server
	for _, sm := range serverMaps(root) {
		for _, name := range sm.servers.keys {
			out = append(out, jsonServer(name, sm.scope, sm.servers.vals[name]))
		}
	}
	return out, nil
}

func jsonServer(name, scope string, entry any) Server {
	s := Server{Name: name, Scope: scope}
	e, ok := entry.(*object)
	if !ok {
		s.Unusual = true
		return s
	}
	if v, has := e.get("command"); has {
		cmd, ok := v.(string)
		s.Command, s.Unusual = cmd, !ok
	}
	if v, has := e.get("args"); has && v != nil {
		list, ok := v.([]any)
		s.Unusual = s.Unusual || !ok
		for _, a := range list {
			str, ok := a.(string)
			if !ok {
				s.Unusual = true
				continue
			}
			s.Args = append(s.Args, str)
		}
	}
	for _, k := range []string{"url", "serverUrl", "httpUrl"} {
		if v, has := e.get(k); has {
			if u, ok := v.(string); ok && s.URL == "" {
				s.URL = u
			}
		}
	}
	s.Env = stringMap(e, "env")
	s.Headers = stringMap(e, "headers")
	if s.Command == "" && s.URL == "" {
		s.Unusual = true
	}
	return s
}

func stringMap(e *object, key string) map[string]string {
	v, has := e.get(key)
	if !has {
		return nil
	}
	o, ok := v.(*object)
	if !ok {
		return nil
	}
	out := make(map[string]string, len(o.keys))
	for _, k := range o.keys {
		if s, ok := o.vals[k].(string); ok {
			out[k] = s
		}
	}
	return out
}

// listTOML reads Codex servers, including their [mcp_servers.NAME.env]
// and [mcp_servers.NAME.http_headers] tables. Values it cannot parse are
// skipped and the entry marked unusual.
func listTOML(data []byte) []Server {
	lines := strings.Split(string(data), "\n")
	blocks, other := parseTOMLServers(lines)
	out := make([]Server, 0, len(blocks)+1)
	index := map[string]int{}
	for _, b := range blocks {
		index[b.name] = len(out)
		out = append(out, Server{Name: b.name, Command: b.command, Args: b.args, URL: b.url, Unusual: b.bad})
	}
	for name, env := range tomlSubTables(lines, ".env") {
		if i, ok := index[name]; ok {
			out[i].Env = env
		}
	}
	for name, headers := range tomlSubTables(lines, ".http_headers") {
		if i, ok := index[name]; ok {
			out[i].Headers = headers
		}
	}
	for name, in := range tomlInlineTables(lines) {
		if i, ok := index[name]; ok {
			out[i].Env = mergeStrings(out[i].Env, in.env)
			out[i].Headers = mergeStrings(out[i].Headers, in.headers)
			out[i].Unusual = out[i].Unusual || in.unusual
		}
	}
	if other {
		out = append(out, Server{Name: "(servers written another way)", Unusual: true})
	}
	return out
}

// tomlSubTables reads [mcp_servers.NAME<suffix>] tables (suffix ".env" or
// ".http_headers") of simple key = "string" lines.
func tomlSubTables(lines []string, suffix string) map[string]map[string]string {
	out := map[string]map[string]string{}
	cur := ""
	for _, raw := range lines {
		line := strings.TrimSuffix(raw, "\r")
		if tomlAnyHeader.MatchString(line) {
			cur = ""
			m := tomlHeader.FindStringSubmatch(line)
			if m == nil {
				continue
			}
			header := tomlDotSpaces.ReplaceAllString(m[1], ".")
			if name, ok := strings.CutSuffix(header, suffix); ok {
				if s := tomlServer.FindStringSubmatch(name); s != nil {
					cur = s[1] + s[2]
					out[cur] = map[string]string{}
				}
			}
			continue
		}
		if cur == "" {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		v, _ := splitTOMLComment(strings.TrimSpace(value))
		if s, ok := parseTOMLString(v); ok {
			out[cur][strings.Trim(strings.TrimSpace(key), `"`)] = s
		}
	}
	return out
}
