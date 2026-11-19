package clients

import (
	"encoding/json"
	"regexp"
	"strings"
)

// Codex keeps MCP servers in ~/.codex/config.toml as tables:
//
//	[mcp_servers.NAME]
//	command = "npx"
//	args = ["-y", "some-server"]
//
// The editor below changes only the command and args lines of those tables
// and leaves every other byte alone, comments included. Entries written in a
// form it does not fully understand (multi-line arrays, inline tables) are
// reported as skipped, never guessed at. A file that uses multi-line strings
// is not edited at all, because a line inside such a string can look like a
// key.

var (
	tomlAnyHeader = regexp.MustCompile(`^\s*\[`)
	tomlHeader    = regexp.MustCompile(`^\s*\[\s*([^\[\]]+?)\s*\]\s*(#.*)?$`)
	tomlDotSpaces = regexp.MustCompile(`\s*\.\s*`)
	tomlServer    = regexp.MustCompile(`^mcp_servers\.(?:"([^"]+)"|([A-Za-z0-9_-]+))$`)
	tomlRootKey   = regexp.MustCompile(`^\s*mcp_servers\s*[.=]`)
	tomlKeyLine   = regexp.MustCompile(`^(\s*)(command|args|url)\s*=\s*(.*)$`)
)

type tomlServerBlock struct {
	name             string
	cmdLine, argLine int // line indexes, -1 when absent
	command          string
	cmdComment       string // trailing comment on the command line, kept on rewrite
	args             []string
	hasURL, bad      bool
}

// ProtectCodexTOML puts Roro in front of every local server in a Codex
// config. When nothing changes it returns data unmodified.
func ProtectCodexTOML(data []byte, w Wrapper) ([]byte, []Result, error) {
	var names Namer
	return rewriteTOML(data, func(b tomlServerBlock) (string, []string, Status) {
		if RunsBehindRoro(b.command, b.args) {
			return "", nil, AlreadyWrapped
		}
		c, a := w.WrapCommand("codex", names.Name(b.name), b.command, b.args)
		return c, a, Wrapped
	})
}

// UnprotectCodexTOML restores the original command of every Codex server
// that runs behind Roro.
func UnprotectCodexTOML(data []byte) ([]byte, []Result, error) {
	return rewriteTOML(data, func(b tomlServerBlock) (string, []string, Status) {
		c, a, ok := Unwrap(b.command, b.args)
		if !ok {
			return "", nil, NotWrapped
		}
		return c, a, Unwrapped
	})
}

func rewriteTOML(data []byte, edit func(tomlServerBlock) (string, []string, Status)) ([]byte, []Result, error) {
	lines := strings.Split(string(data), "\n")
	blocks, other := parseTOMLServers(lines)
	var results []Result
	if strings.Contains(string(data), `"""`) || strings.Contains(string(data), "'''") {
		for _, b := range blocks {
			results = append(results, Result{Server: b.name, Status: SkippedUnsupported})
		}
		return data, results, nil
	}
	insertAfter := map[int]string{}
	changed := false
	for _, b := range blocks {
		status := Status("")
		switch {
		case b.bad:
			status = SkippedUnsupported
		case b.cmdLine < 0 && b.hasURL:
			status = SkippedRemote
		case b.cmdLine < 0:
			status = SkippedUnsupported
		}
		if status == "" {
			var c string
			var a []string
			c, a, status = edit(b)
			if status == Wrapped || status == Unwrapped {
				changed = true
				indent, cr := lineIndent(lines[b.cmdLine])
				lines[b.cmdLine] = indent + "command = " + tomlString(c) + b.cmdComment + cr
				if b.argLine >= 0 {
					argIndent, argCR := lineIndent(lines[b.argLine])
					lines[b.argLine] = argIndent + "args = " + tomlArray(a) + argCR
				} else {
					insertAfter[b.cmdLine] = indent + "args = " + tomlArray(a) + cr
				}
			}
		}
		results = append(results, Result{Server: b.name, Status: status})
	}
	if other {
		results = append(results, Result{Server: "(servers written another way)", Status: SkippedUnsupported})
	}
	if !changed {
		return data, results, nil
	}
	out := make([]string, 0, len(lines)+len(insertAfter))
	for i, l := range lines {
		out = append(out, l)
		if extra, ok := insertAfter[i]; ok {
			out = append(out, extra)
		}
	}
	return []byte(strings.Join(out, "\n")), results, nil
}

// parseTOMLServers finds the [mcp_servers.NAME] tables. other is true when
// the file also defines servers in a form this editor does not handle
// (dotted keys, an inline table, or keys directly under [mcp_servers]).
func parseTOMLServers(lines []string) (blocks []tomlServerBlock, other bool) {
	cur := -1
	inRoot, inServersTable := true, false
	for i, raw := range lines {
		line := strings.TrimSuffix(raw, "\r")
		if tomlAnyHeader.MatchString(line) {
			// Every header, including [[array]] ones, ends the current table.
			cur, inRoot, inServersTable = -1, false, false
			m := tomlHeader.FindStringSubmatch(line)
			if m == nil {
				continue
			}
			header := tomlDotSpaces.ReplaceAllString(m[1], ".")
			if header == "mcp_servers" {
				inServersTable = true
			}
			if s := tomlServer.FindStringSubmatch(header); s != nil {
				blocks = append(blocks, tomlServerBlock{name: s[1] + s[2], cmdLine: -1, argLine: -1})
				cur = len(blocks) - 1
			}
			continue
		}
		trimmed := strings.TrimSpace(line)
		if (inRoot && tomlRootKey.MatchString(line)) || (inServersTable && trimmed != "" && !strings.HasPrefix(trimmed, "#")) {
			other = true
		}
		if cur < 0 {
			continue
		}
		m := tomlKeyLine.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		b := &blocks[cur]
		value, comment := splitTOMLComment(m[3])
		switch m[2] {
		case "url":
			b.hasURL = true
		case "command":
			s, ok := parseTOMLString(value)
			b.cmdLine, b.command, b.cmdComment, b.bad = i, s, comment, b.bad || !ok || s == ""
		case "args":
			a, ok := parseTOMLStringArray(value)
			b.argLine, b.args, b.bad = i, a, b.bad || !ok
		}
	}
	return blocks, other
}

func lineIndent(raw string) (indent, cr string) {
	if strings.HasSuffix(raw, "\r") {
		cr = "\r"
	}
	return raw[:len(raw)-len(strings.TrimLeft(raw, " \t"))], cr
}

// splitTOMLComment separates a value from a trailing comment that is
// outside any string. The comment keeps its leading spaces.
func splitTOMLComment(v string) (value, comment string) {
	var quote byte
	for i := 0; i < len(v); i++ {
		c := v[i]
		switch {
		case quote == '"' && c == '\\':
			i++
		case quote != 0 && c == quote:
			quote = 0
		case quote == 0 && (c == '"' || c == '\''):
			quote = c
		case quote == 0 && c == '#':
			value = strings.TrimRight(v[:i], " \t")
			return value, v[len(value):]
		}
	}
	return strings.TrimSpace(v), ""
}

// parseTOMLString reads a single-line basic ("...") or literal ('...')
// string. Basic strings are accepted when they are also valid JSON strings,
// which covers ordinary paths and flags.
func parseTOMLString(v string) (string, bool) {
	if len(v) >= 2 && v[0] == '\'' && v[len(v)-1] == '\'' && !strings.Contains(v[1:len(v)-1], "'") {
		return v[1 : len(v)-1], true
	}
	if len(v) >= 2 && v[0] == '"' && !strings.HasPrefix(v, `"""`) {
		var s string
		if err := json.Unmarshal([]byte(v), &s); err == nil {
			return s, true
		}
	}
	return "", false
}

// parseTOMLStringArray reads a single-line array of strings.
func parseTOMLStringArray(v string) ([]string, bool) {
	if len(v) < 2 || v[0] != '[' || v[len(v)-1] != ']' {
		return nil, false
	}
	var out []string
	rest := strings.TrimSpace(v[1 : len(v)-1])
	for rest != "" {
		end := tomlStringEnd(rest)
		if end < 0 {
			return nil, false
		}
		s, ok := parseTOMLString(rest[:end])
		if !ok {
			return nil, false
		}
		out = append(out, s)
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

// tomlStringEnd returns the index just past the string that starts s.
func tomlStringEnd(s string) int {
	if s == "" || (s[0] != '"' && s[0] != '\'') {
		return -1
	}
	for i := 1; i < len(s); i++ {
		if s[0] == '"' && s[i] == '\\' {
			i++
			continue
		}
		if s[i] == s[0] {
			return i + 1
		}
	}
	return -1
}

func tomlString(s string) string {
	b, _ := json.Marshal(s) // a JSON string without HTML escapes is a TOML basic string
	return strings.NewReplacer(`\u003c`, "<", `\u003e`, ">", `\u0026`, "&", "\u007f", `\u007f`).Replace(string(b))
}

func tomlArray(items []string) string {
	quoted := make([]string, len(items))
	for i, it := range items {
		quoted[i] = tomlString(it)
	}
	return "[" + strings.Join(quoted, ", ") + "]"
}
