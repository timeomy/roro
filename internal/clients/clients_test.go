package clients

import (
	"reflect"
	"strings"
	"testing"
)

var w = Wrapper{Roro: "/usr/local/bin/roro", Config: "/home/me/.roro/roro.yaml"}

func TestWrapAndUnwrapRoundTrip(t *testing.T) {
	cmd, args := w.WrapCommand("cursor", ServerName("my files"), "npx", []string{"-y", "server-filesystem", "/tmp"})
	if cmd != "/usr/local/bin/roro" {
		t.Fatalf("command = %q", cmd)
	}
	want := []string{"--config", "/home/me/.roro/roro.yaml", "wrap", "--agent", "cursor", "--server", "my-files", "--", "npx", "-y", "server-filesystem", "/tmp"}
	if !reflect.DeepEqual(args, want) {
		t.Fatalf("args = %q\nwant  %q", args, want)
	}
	oc, oa, ok := Unwrap(cmd, args)
	if !ok || oc != "npx" || !reflect.DeepEqual(oa, []string{"-y", "server-filesystem", "/tmp"}) {
		t.Fatalf("Unwrap = %q %q %v", oc, oa, ok)
	}
}

func TestUnwrapOnlyUndoesWhatProtectWrote(t *testing.T) {
	cases := [][]string{
		{"npx", "--config", "c", "wrap", "--agent", "a", "--server", "s", "--", "x"}, // not roro
		{"/bin/roro", "serve"},
		{"/bin/roro", "wrap", "--agent", "a", "--", "x"}, // written by hand
		{"/bin/roro", "--config", "c", "wrap", "--agent", "a", "--server", "s", "--"},
	}
	for _, c := range cases {
		if _, _, ok := Unwrap(c[0], c[1:]); ok {
			t.Errorf("Unwrap(%q) = ok, want left alone", c)
		}
	}
	// A hand-written wrap still counts as protected, so protect does not wrap it twice.
	if !RunsBehindRoro("/bin/roro", []string{"wrap", "--agent", "a", "--", "x"}) {
		t.Error("hand-written roro wrap not recognised")
	}
	if !RunsBehindRoro(`C:\Tools\roro.exe`, []string{"--config", "c", "wrap", "--", "node"}) {
		t.Error("roro.exe wrap not recognised")
	}
	if RunsBehindRoro("npx", []string{"wrap", "--", "x"}) || RunsBehindRoro("/bin/roro", []string{"serve"}) || RunsBehindRoro("/bin/roro", []string{"--", "wrap"}) {
		t.Error("a command that is not roro wrap was recognised as protected")
	}
	// The original's own "--" and "wrap" arguments survive the round trip.
	c, a := w.WrapCommand("cursor", "s", "roro", []string{"wrap", "--", "--x"})
	oc, oa, ok := Unwrap(c, a)
	if !ok || oc != "roro" || !reflect.DeepEqual(oa, []string{"wrap", "--", "--x"}) {
		t.Errorf("round trip = %q %q %v", oc, oa, ok)
	}
}

func TestNamerKeepsDifferentServersApart(t *testing.T) {
	var n Namer
	first, second, again := n.Name("a b"), n.Name("a-b"), n.Name("a b")
	if first != "a-b" || second == first || again != first {
		t.Errorf("names = %q %q %q", first, second, again)
	}
	long := strings.Repeat("x", 70)
	l1, l2 := n.Name(long+"1"), n.Name(long+"2")
	if l1 == l2 || len(l1) > 64 || len(l2) > 64 {
		t.Errorf("long names = %q %q", l1, l2)
	}
}

func TestProtectJSONRefusesAmbiguousFiles(t *testing.T) {
	for name, in := range map[string]string{
		"duplicate key": `{"mcpServers":{"a":{"command":"x","command":"y"}}}`,
		"invalid utf8":  "{\"mcpServers\":{\"a\":{\"command\":\"x\xff\"}}}",
	} {
		if _, _, err := ProtectJSON([]byte(in), "cursor", w); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	out, res, err := ProtectJSON([]byte(`{"mcpServers":{"w":{"serverUrl":"https://x"},"hand":{"command":"roro","args":["wrap","--","x"]}}}`), "windsurf", w)
	if err != nil || statuses(res)["w"] != SkippedRemote || statuses(res)["hand"] != AlreadyWrapped {
		t.Errorf("res = %v err = %v", res, err)
	}
	_, res, _ = UnprotectJSON(out)
	if statuses(res)["hand"] != NotWrapped {
		t.Errorf("unprotect touched a hand-written wrap: %v", res)
	}
}

func TestCodexTOMLDoesNotEditOtherTables(t *testing.T) {
	in := "[mcp_servers.a]\ncommand = \"npx\"  # keep me\r\nargs = [\"x\\u007f\"]\n\n[[profiles]]\ncommand = \"evil\"\nargs = [\"q\"]\n\n[ mcp_servers . spaced ]\ncommand = 'srv'\n\n[mcp_servers]\nb.command = \"dotted\"\n"
	out, res, err := ProtectCodexTOML([]byte(in), w)
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if !strings.Contains(s, "[[profiles]]\ncommand = \"evil\"\nargs = [\"q\"]") {
		t.Errorf("array-of-tables entry was edited:\n%s", s)
	}
	if !strings.Contains(s, `command = "/usr/local/bin/roro"  # keep me`+"\r\n") || !strings.Contains(s, `"x\u007f"]`) {
		t.Errorf("comment, CRLF, or DEL escaping lost:\n%q", s)
	}
	got := statuses(res)
	if got["a"] != Wrapped || got["spaced"] != Wrapped || got["(servers written another way)"] != SkippedUnsupported {
		t.Errorf("statuses = %v", got)
	}
	back, _, _ := UnprotectCodexTOML(out)
	want := strings.Replace(in, "command = 'srv'\n", "command = \"srv\"\nargs = []\n", 1)
	if string(back) != want {
		t.Errorf("round trip:\n%q\nwant\n%q", back, want)
	}

	multi := "[mcp_servers.m]\ncommand = \"npx\"\nnote = \"\"\"\nargs = [\"z\"]\n\"\"\"\n"
	out, res, _ = ProtectCodexTOML([]byte(multi), w)
	if string(out) != multi || statuses(res)["m"] != SkippedUnsupported {
		t.Errorf("a file with a multi-line string was edited: %v\n%s", res, out)
	}
}

func TestServerNameIsSafe(t *testing.T) {
	for in, want := range map[string]string{
		"github": "github", "My Files!": "My-Files", "  ": "server", "@scope/pkg": "scope-pkg",
		strings.Repeat("a", 80): strings.Repeat("a", 64),
	} {
		if got := ServerName(in); got != want {
			t.Errorf("ServerName(%q) = %q, want %q", in, got, want)
		}
	}
}

const cursorJSON = `{
  "theme": "dark",
  "mcpServers": {
    "zeta": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem", "/Users/me/a <b> & c"],
      "env": {"TOKEN": "abc"}
    },
    "remote": {"url": "https://example.com/mcp"},
    "alpha": {"command": "/opt/tools/server"},
    "odd": {"command": 7}
  },
  "big": 12345678901234567890
}
`

func TestProtectJSON(t *testing.T) {
	out, res, err := ProtectJSON([]byte(cursorJSON), "cursor", w)
	if err != nil {
		t.Fatal(err)
	}
	got := statuses(res)
	want := map[string]Status{"zeta": Wrapped, "remote": SkippedRemote, "alpha": Wrapped, "odd": SkippedUnsupported}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("statuses = %v, want %v", got, want)
	}
	s := string(out)
	for _, must := range []string{
		`"theme": "dark"`, `"big": 12345678901234567890`, `"TOKEN": "abc"`, `/Users/me/a <b> & c`,
		`"command": "/usr/local/bin/roro"`, `"--server"`, `"zeta"`, `"url": "https://example.com/mcp"`,
	} {
		if !strings.Contains(s, must) {
			t.Errorf("output lost %s\n%s", must, s)
		}
	}
	// Key order is preserved: zeta stays before alpha, theme before mcpServers.
	if !(strings.Index(s, `"zeta"`) < strings.Index(s, `"alpha"`) && strings.Index(s, `"theme"`) < strings.Index(s, `"mcpServers"`)) {
		t.Errorf("key order changed:\n%s", s)
	}

	// Protecting twice changes nothing.
	out2, res2, err := ProtectJSON(out, "cursor", w)
	if err != nil {
		t.Fatal(err)
	}
	if string(out2) != string(out) {
		t.Error("second protect rewrote the file")
	}
	if statuses(res2)["zeta"] != AlreadyWrapped {
		t.Errorf("second protect: %v", statuses(res2))
	}

	// Unprotect restores the original commands.
	back, res3, err := UnprotectJSON(out)
	if err != nil {
		t.Fatal(err)
	}
	if statuses(res3)["zeta"] != Unwrapped || statuses(res3)["alpha"] != Unwrapped {
		t.Errorf("unprotect: %v", statuses(res3))
	}
	for _, must := range []string{`"command": "npx"`, `"command": "/opt/tools/server"`, `"@modelcontextprotocol/server-filesystem"`} {
		if !strings.Contains(string(back), must) {
			t.Errorf("unprotect lost %s\n%s", must, back)
		}
	}
	if strings.Contains(string(back), "roro") {
		t.Errorf("unprotect left roro behind:\n%s", back)
	}
}

func TestProtectJSONClaudeCodeProjects(t *testing.T) {
	in := `{"mcpServers":{"a":{"type":"stdio","command":"a-server","args":[]}},"projects":{"/work/x":{"mcpServers":{"b":{"command":"b-server"}},"history":[1,2]},"/work/y":{}}}`
	out, res, err := ProtectJSON([]byte(in), "claude-code", w)
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 2 || res[0].Status != Wrapped || res[1].Status != Wrapped || res[1].Scope != "/work/x" {
		t.Fatalf("results = %+v", res)
	}
	if strings.Count(string(out), `"/usr/local/bin/roro"`) != 2 || !strings.Contains(string(out), `"history"`) {
		t.Errorf("output:\n%s", out)
	}
}

func TestProtectJSONNothingToDoReturnsInputUntouched(t *testing.T) {
	in := "{ \"mcpServers\" : {\"r\":{\"url\":\"https://x\"}} }"
	out, _, err := ProtectJSON([]byte(in), "cursor", w)
	if err != nil || string(out) != in {
		t.Fatalf("out = %q err = %v", out, err)
	}
	if _, _, err := ProtectJSON([]byte("{not json"), "cursor", w); err == nil {
		t.Error("invalid JSON was accepted")
	}
	if _, _, err := ProtectJSON([]byte(`[1]`), "cursor", w); err == nil {
		t.Error("a non-object document was accepted")
	}
}

const codexTOML = `# my codex config
model = "gpt-5"

[mcp_servers.files]
command = "npx"   # the launcher
args = ["-y", "@modelcontextprotocol/server-filesystem", "/Users/me/docs"]

[mcp_servers.files.env]
TOKEN = "abc"

[mcp_servers.plain]
command = 'my-server'

[mcp_servers.remote]
url = "https://example.com/mcp"

[mcp_servers.multi]
command = "node"
args = [
  "server.js",
]

[other]
command = "untouched"
`

func TestProtectCodexTOML(t *testing.T) {
	out, res, err := ProtectCodexTOML([]byte(codexTOML), w)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]Status{"files": Wrapped, "plain": Wrapped, "remote": SkippedRemote, "multi": SkippedUnsupported}
	if got := statuses(res); !reflect.DeepEqual(got, want) {
		t.Fatalf("statuses = %v, want %v", got, want)
	}
	s := string(out)
	for _, must := range []string{
		"# my codex config", `model = "gpt-5"`, `TOKEN = "abc"`, "[other]\ncommand = \"untouched\"",
		`command = "/usr/local/bin/roro"`,
		`args = ["--config", "/home/me/.roro/roro.yaml", "wrap", "--agent", "codex", "--server", "files", "--", "npx", "-y", "@modelcontextprotocol/server-filesystem", "/Users/me/docs"]`,
		`args = ["--config", "/home/me/.roro/roro.yaml", "wrap", "--agent", "codex", "--server", "plain", "--", "my-server"]`,
		"command = \"node\"\nargs = [\n  \"server.js\",\n]",
	} {
		if !strings.Contains(s, must) {
			t.Errorf("output lost %q\n%s", must, s)
		}
	}
	out2, res2, _ := ProtectCodexTOML(out, w)
	if string(out2) != s || statuses(res2)["files"] != AlreadyWrapped {
		t.Errorf("second protect changed the file or status: %v", statuses(res2))
	}
	back, res3, err := UnprotectCodexTOML(out)
	if err != nil {
		t.Fatal(err)
	}
	if statuses(res3)["files"] != Unwrapped || statuses(res3)["plain"] != Unwrapped {
		t.Errorf("unprotect: %v", statuses(res3))
	}
	for _, must := range []string{`command = "npx"`, `args = ["-y", "@modelcontextprotocol/server-filesystem", "/Users/me/docs"]`, `command = "my-server"`} {
		if !strings.Contains(string(back), must) {
			t.Errorf("unprotect lost %q\n%s", must, back)
		}
	}
	if strings.Contains(string(back), "roro") {
		t.Errorf("unprotect left roro behind:\n%s", back)
	}
}

func TestLocations(t *testing.T) {
	mac := Locations("/Users/me", "darwin", "")
	byClient := map[string]string{}
	for _, l := range mac {
		byClient[l.Client] = l.Path
	}
	for client, want := range map[string]string{
		"claude-code":    "/Users/me/.claude.json",
		"claude-desktop": "/Users/me/Library/Application Support/Claude/claude_desktop_config.json",
		"cursor":         "/Users/me/.cursor/mcp.json",
		"windsurf":       "/Users/me/.codeium/windsurf/mcp_config.json",
		"codex":          "/Users/me/.codex/config.toml",
	} {
		if byClient[client] != want {
			t.Errorf("%s: %q, want %q", client, byClient[client], want)
		}
	}
	for _, l := range Locations(`C:\Users\me`, "windows", `C:\Users\me\AppData\Roaming`) {
		if l.Client == "claude-desktop" && !strings.Contains(l.Path, "AppData") {
			t.Errorf("windows claude desktop path = %q", l.Path)
		}
	}
}

func statuses(res []Result) map[string]Status {
	m := map[string]Status{}
	for _, r := range res {
		m[r.Server] = r.Status
	}
	return m
}
