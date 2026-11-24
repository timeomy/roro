package clients

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"
)

// object is a JSON object that remembers the order of its keys, so a
// rewritten configuration file keeps the layout its owner chose.
type object struct {
	keys []string
	vals map[string]any
}

func (o *object) get(k string) (any, bool) { v, ok := o.vals[k]; return v, ok }

func (o *object) set(k string, v any) {
	if _, ok := o.vals[k]; !ok {
		o.keys = append(o.keys, k)
	}
	o.vals[k] = v
}

func decodeJSON(data []byte) (*object, error) {
	if !utf8.Valid(data) {
		return nil, errors.New("the file is not valid UTF-8 text")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	v, err := decodeValue(dec)
	if err != nil {
		return nil, explainSyntax(err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("unexpected content after the JSON document")
	}
	root, ok := v.(*object)
	if !ok {
		return nil, errors.New("the configuration is not a JSON object")
	}
	return root, nil
}

func decodeValue(dec *json.Decoder) (any, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	delim, isDelim := tok.(json.Delim)
	if !isDelim {
		return tok, nil
	}
	switch delim {
	case '{':
		o := &object{vals: map[string]any{}}
		for dec.More() {
			kt, err := dec.Token()
			if err != nil {
				return nil, err
			}
			v, err := decodeValue(dec)
			if err != nil {
				return nil, err
			}
			key := kt.(string)
			if _, dup := o.vals[key]; dup {
				return nil, fmt.Errorf("the key %q appears twice in one object", key)
			}
			o.set(key, v)
		}
		_, err := dec.Token()
		return o, err
	case '[':
		arr := []any{}
		for dec.More() {
			v, err := decodeValue(dec)
			if err != nil {
				return nil, err
			}
			arr = append(arr, v)
		}
		_, err := dec.Token()
		return arr, err
	}
	return nil, fmt.Errorf("unexpected %q", delim)
}

func encodeJSON(root *object) []byte {
	var b bytes.Buffer
	writeValue(&b, root, 0)
	b.WriteByte('\n')
	return b.Bytes()
}

func writeValue(b *bytes.Buffer, v any, depth int) {
	indent := func(d int) {
		b.WriteByte('\n')
		for range d {
			b.WriteString("  ")
		}
	}
	switch t := v.(type) {
	case *object:
		if len(t.keys) == 0 {
			b.WriteString("{}")
			return
		}
		b.WriteByte('{')
		for i, k := range t.keys {
			if i > 0 {
				b.WriteByte(',')
			}
			indent(depth + 1)
			writeScalar(b, k)
			b.WriteString(": ")
			writeValue(b, t.vals[k], depth+1)
		}
		indent(depth)
		b.WriteByte('}')
	case []any:
		if len(t) == 0 {
			b.WriteString("[]")
			return
		}
		b.WriteByte('[')
		for i, e := range t {
			if i > 0 {
				b.WriteByte(',')
			}
			indent(depth + 1)
			writeValue(b, e, depth+1)
		}
		indent(depth)
		b.WriteByte(']')
	default:
		writeScalar(b, v)
	}
}

// writeScalar writes a string, number, bool, or null without HTML escaping,
// so paths and URLs stay readable.
func writeScalar(b *bytes.Buffer, v any) {
	enc := json.NewEncoder(b)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v) // strings, json.Number, bool, nil cannot fail
	b.Truncate(b.Len() - 1)
}

// serverMaps returns every "mcpServers" object in the document: the
// user-wide one, then Claude Code's per-project ones.
func serverMaps(root *object) []scoped {
	var out []scoped
	if m, ok := root.vals["mcpServers"].(*object); ok {
		out = append(out, scoped{servers: m})
	}
	if projects, ok := root.vals["projects"].(*object); ok {
		for _, p := range projects.keys {
			proj, ok := projects.vals[p].(*object)
			if !ok {
				continue
			}
			if m, ok := proj.vals["mcpServers"].(*object); ok {
				out = append(out, scoped{scope: p, servers: m})
			}
		}
	}
	return out
}

type scoped struct {
	scope   string
	servers *object
}

// stdioEntry reads the command line of a server entry.
func stdioEntry(entry any) (e *object, command string, args []string, status Status) {
	e, ok := entry.(*object)
	if !ok {
		return nil, "", nil, SkippedUnsupported
	}
	rawCmd, hasCmd := e.get("command")
	if !hasCmd {
		for _, k := range []string{"url", "serverUrl", "httpUrl"} {
			if _, hasURL := e.get(k); hasURL {
				return e, "", nil, SkippedRemote
			}
		}
		return e, "", nil, SkippedUnsupported
	}
	command, ok = rawCmd.(string)
	if !ok || command == "" {
		return e, "", nil, SkippedUnsupported
	}
	if rawArgs, has := e.get("args"); has && rawArgs != nil {
		list, ok := rawArgs.([]any)
		if !ok {
			return e, "", nil, SkippedUnsupported
		}
		for _, a := range list {
			s, ok := a.(string)
			if !ok {
				return e, "", nil, SkippedUnsupported
			}
			args = append(args, s)
		}
	}
	return e, command, args, ""
}

func setCommand(e *object, command string, args []string) {
	list := make([]any, len(args))
	for i, a := range args {
		list[i] = a
	}
	e.set("command", command)
	e.set("args", list)
}

// ProtectJSON puts Roro in front of every local (stdio) server in a JSON
// client configuration. When nothing changes it returns data unmodified.
func ProtectJSON(data []byte, agent string, w Wrapper) ([]byte, []Result, error) {
	var names Namer
	return rewriteJSON(data, func(name string, e *object, command string, args []string) Status {
		if RunsBehindRoro(command, args) {
			return AlreadyWrapped
		}
		c, a := w.WrapCommand(agent, names.Name(name), command, args)
		setCommand(e, c, a)
		return Wrapped
	})
}

// UnprotectJSON restores the original command of every server that runs
// behind Roro.
func UnprotectJSON(data []byte) ([]byte, []Result, error) {
	return rewriteJSON(data, func(_ string, e *object, command string, args []string) Status {
		c, a, ok := Unwrap(command, args)
		if !ok {
			return NotWrapped
		}
		setCommand(e, c, a)
		return Unwrapped
	})
}

func rewriteJSON(data []byte, edit func(name string, e *object, command string, args []string) Status) ([]byte, []Result, error) {
	root, err := decodeJSON(data)
	if err != nil {
		return nil, nil, err
	}
	var results []Result
	changed := false
	for _, sm := range serverMaps(root) {
		for _, name := range sm.servers.keys {
			e, command, args, status := stdioEntry(sm.servers.vals[name])
			if status == "" {
				status = edit(name, e, command, args)
				changed = changed || status == Wrapped || status == Unwrapped
			}
			results = append(results, Result{Server: name, Scope: sm.scope, Status: status})
		}
	}
	if !changed {
		return data, results, nil
	}
	return encodeJSON(root), results, nil
}

// explainSyntax says why a file that looks like JSON was refused, when the
// cause is a comment or a trailing comma (common in editor-written configs).
func explainSyntax(err error) error {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "invalid character '/'"),
		strings.Contains(msg, "invalid character '}' looking for beginning of object key string"),
		strings.Contains(msg, "invalid character ']' looking for beginning of value"),
		strings.Contains(msg, "invalid character ',' looking for beginning of value"):
		return errors.New("the file is not plain JSON (comments or trailing commas are not supported)")
	}
	return err
}
