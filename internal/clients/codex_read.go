package clients

import (
	"fmt"
	"slices"

	"github.com/BurntSushi/toml"
)

// listTOML reads Codex servers with a full TOML parser, so multi-line
// strings, inline tables and sub-tables are all seen. A file that is not
// valid TOML is an error, never a partial read. (Editing still uses the
// line editor in toml.go, which keeps comments and layout.)
func listTOML(data []byte) ([]Server, error) {
	var doc map[string]any
	if _, err := toml.Decode(string(data), &doc); err != nil {
		return nil, fmt.Errorf("the file is not valid TOML: %w", err)
	}
	raw, has := doc["mcp_servers"]
	if !has {
		return nil, nil
	}
	table, ok := raw.(map[string]any)
	if !ok {
		return []Server{{Name: "mcp_servers", Unusual: true}}, nil
	}
	names := make([]string, 0, len(table))
	for name := range table {
		names = append(names, name)
	}
	slices.Sort(names)
	out := make([]Server, 0, len(names))
	for _, name := range names {
		out = append(out, codexServer(name, table[name]))
	}
	return out, nil
}

func codexServer(name string, v any) Server {
	s := Server{Name: name}
	e, ok := v.(map[string]any)
	if !ok {
		s.Unusual = true
		return s
	}
	if c, has := e["command"]; has {
		s.Command, ok = c.(string)
		s.Unusual = !ok
	}
	if a, has := e["args"]; has {
		list, ok := a.([]any)
		s.Unusual = s.Unusual || !ok
		for _, item := range list {
			str, ok := item.(string)
			if !ok {
				s.Unusual = true
				continue
			}
			s.Args = append(s.Args, str)
		}
	}
	if u, has := e["url"]; has {
		s.URL, _ = u.(string)
	}
	if en, has := e["enabled"]; has && en == false {
		s.Disabled = true
	}
	s.Env, s.Unusual = codexTable(e["env"], s.Unusual)
	s.Headers, s.Unusual = codexTable(e["http_headers"], s.Unusual)
	if s.Command == "" && s.URL == "" {
		s.Unusual = true
	}
	return s
}

// codexTable reads a table of scalar settings. Anything else marks the
// server unusual.
func codexTable(v any, unusual bool) (map[string]string, bool) {
	if v == nil {
		return nil, unusual
	}
	t, ok := v.(map[string]any)
	if !ok {
		return nil, true
	}
	out := make(map[string]string, len(t))
	for k, val := range t {
		s, ok := scalarString(val)
		if !ok {
			unusual = true
			continue
		}
		out[k] = s
	}
	return out, unusual
}
