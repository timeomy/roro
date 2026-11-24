package clients

import (
	"encoding/json"
	"strconv"
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
	// Disabled is true when the client is told not to start this server
	// ("disabled": true, or enabled = false in Codex).
	Disabled bool
}

// Remote reports whether the entry is a remote (HTTP) server.
func (s Server) Remote() bool { return s.Command == "" && s.URL != "" }

// ListServers returns every MCP server entry in a client configuration
// file, without running anything.
func ListServers(format Format, data []byte) ([]Server, error) {
	if format == FormatCodexTOML {
		return listTOML(data)
	}
	root, err := decodeJSON(data)
	if err != nil {
		return nil, err
	}
	var out []Server
	if v, has := root.get("mcpServers"); has {
		if _, ok := v.(*object); !ok {
			out = append(out, Server{Name: "mcpServers", Unusual: true})
		}
	}
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
	if v, has := e.get("disabled"); has && v == true {
		s.Disabled = true
	}
	if v, has := e.get("enabled"); has && v == false {
		s.Disabled = true
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
		if s, ok := scalarString(o.vals[k]); ok {
			out[k] = s
		}
	}
	return out
}

// scalarString returns a string, number, or boolean setting as text, so a
// secret written as a number is still checked.
func scalarString(v any) (string, bool) {
	switch t := v.(type) {
	case string:
		return t, true
	case json.Number:
		return t.String(), true
	case bool:
		return strconv.FormatBool(t), true
	case int64:
		return strconv.FormatInt(t, 10), true
	case float64:
		return strconv.FormatFloat(t, 'g', -1, 64), true
	}
	return "", false
}
