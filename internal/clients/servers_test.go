package clients

import (
	"strings"
	"testing"
)

func TestListServersJSON(t *testing.T) {
	data := []byte(`{
  "mcpServers": {
    "local": {"command": "npx", "args": ["-y", "srv"], "env": {"A": "1", "N": 2}},
    "remote": {"serverUrl": "https://x/mcp", "headers": {"Authorization": "Bearer t"}},
    "badargs": {"command": "srv", "args": [1]},
    "badcmd": {"command": 5},
    "empty": {},
    "notobj": "x",
    "badenv": {"command": "srv", "env": "x"}
  },
  "projects": {"/p": {"mcpServers": {"proj": {"command": "srv"}}}, "/q": "x"}
}`)
	got, err := ListServers(FormatJSON, data)
	if err != nil {
		t.Fatal(err)
	}
	by := map[string]Server{}
	for _, s := range got {
		by[s.Name] = s
	}
	if len(got) != 8 {
		t.Fatalf("got %d servers: %+v", len(got), got)
	}
	if s := by["local"]; s.Command != "npx" || len(s.Args) != 2 || s.Env["A"] != "1" || s.Env["N"] != "2" || len(s.Env) != 2 || s.Unusual || s.Remote() {
		t.Fatalf("local = %+v", s)
	}
	if s := by["remote"]; s.URL != "https://x/mcp" || s.Headers["Authorization"] != "Bearer t" || !s.Remote() {
		t.Fatalf("remote = %+v", s)
	}
	for _, n := range []string{"badargs", "badcmd", "empty", "notobj"} {
		if !by[n].Unusual {
			t.Errorf("%s should be unusual", n)
		}
	}
	if by["badenv"].Env != nil || by["badenv"].Unusual {
		t.Errorf("badenv = %+v", by["badenv"])
	}
	if by["proj"].Scope != "/p" {
		t.Errorf("proj scope = %q", by["proj"].Scope)
	}
	if _, err := ListServers(FormatJSON, []byte("[1]")); err == nil {
		t.Fatal("non-object accepted")
	}
}

func mustTOML(t *testing.T, data string) []Server {
	t.Helper()
	got, err := listTOML([]byte(data))
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func TestListServersTOML(t *testing.T) {
	got := mustTOML(t, "[mcp_servers.a]\ncommand = \"uvx\"\nargs = [\"srv\"]\n\n[mcp_servers.a.env]\nKEY = \"v\" # note\n\"QUOTED\" = 'w'\nNUM = 4096\nbad = [1]\n\n[mcp_servers.r]\nurl = \"https://x/mcp\"\nenabled = false\n\n[other]\nk = \"v\"\n")
	if len(got) != 2 {
		t.Fatalf("got %+v", got)
	}
	a, r := got[0], got[1]
	if a.Command != "uvx" || a.Env["KEY"] != "v" || a.Env["QUOTED"] != "w" || a.Env["NUM"] != "4096" || len(a.Env) != 3 || !a.Unusual {
		t.Fatalf("a = %+v", a)
	}
	if r.URL != "https://x/mcp" || !r.Remote() || !r.Disabled {
		t.Fatalf("r = %+v", r)
	}
	dotted := mustTOML(t, "mcp_servers.x = { command = \"a\", env = { K = \"v\" } }\n")
	if len(dotted) != 1 || dotted[0].Command != "a" || dotted[0].Env["K"] != "v" {
		t.Fatalf("dotted form = %+v", dotted)
	}
	if got := mustTOML(t, "model = \"x\"\n"); len(got) != 0 {
		t.Fatalf("no servers = %+v", got)
	}
	if got := mustTOML(t, "mcp_servers = 1\n"); len(got) != 1 || !got[0].Unusual {
		t.Fatalf("non-table = %+v", got)
	}
}

func TestListServersTOMLMultiLineSecret(t *testing.T) {
	got := mustTOML(t, "[mcp_servers.a]\ncommand = \"x\"\n[mcp_servers.a.env]\nGITHUB_TOKEN = \"\"\"ghp_abc\"\"\"\n")
	if got[0].Env["GITHUB_TOKEN"] != "ghp_abc" {
		t.Fatalf("env = %+v", got[0].Env)
	}
}

func TestListServersTOMLRejectsBrokenFiles(t *testing.T) {
	for _, bad := range []string{"[mcp_servers.a]\nenv = {K=\"v\"\n", "[ broken\n", "a = \"unterminated\n"} {
		if _, err := ListServers(FormatCodexTOML, []byte(bad)); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestListServersTOMLHeaders(t *testing.T) {
	got := mustTOML(t, "[mcp_servers.r]\nurl = \"https://x/mcp\"\nbearer_token_env_var = \"GH\"\n\n[mcp_servers.r.http_headers]\nAuthorization = \"Bearer abc\" # c\n\"X-Key\" = 'k'\n\n[mcp_servers.r.env_http_headers]\nX-Other = \"OTHER_ENV\"\n\n[mcp_servers.r.env]\nA = \"1\"\n")
	if len(got) != 1 {
		t.Fatalf("got %+v", got)
	}
	r := got[0]
	if r.Headers["Authorization"] != "Bearer abc" || r.Headers["X-Key"] != "k" || len(r.Headers) != 2 {
		t.Fatalf("headers = %+v", r.Headers)
	}
	if r.Env["A"] != "1" || len(r.Env) != 1 {
		t.Fatalf("env = %+v", r.Env)
	}
}

func TestListServersTOMLInlineTables(t *testing.T) {
	tests := []struct {
		name    string
		toml    string
		env     map[string]string
		headers map[string]string
		unusual bool
	}{
		{"env and headers", "[mcp_servers.a]\ncommand = \"x\"\nenv = { K = \"v\", \"Q-2\" = 'w' } # c\nhttp_headers = { \"X-Api-Key\" = \"s,}\" }\n", map[string]string{"K": "v", "Q-2": "w"}, map[string]string{"X-Api-Key": "s,}"}, false},
		{"empty table", "[mcp_servers.a]\ncommand = \"x\"\nenv = {}\n", nil, nil, false},
		{"number value", "[mcp_servers.a]\ncommand = \"x\"\nenv = { K = 1 }\n", map[string]string{"K": "1"}, nil, false},
		{"nested table", "[mcp_servers.a]\ncommand = \"x\"\nenv = { K = { a = \"b\" } }\n", nil, nil, true},
		{"not a table", "[mcp_servers.a]\ncommand = \"x\"\nhttp_headers = \"nope\"\n", nil, nil, true},
		{"bad args", "[mcp_servers.a]\ncommand = \"x\"\nargs = [1]\n", nil, nil, true},
		{"bad command", "[mcp_servers.a]\ncommand = 1\n", nil, nil, true},
		{"not a server table", "[mcp_servers]\na = \"x\"\n", nil, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := mustTOML(t, tt.toml)
			if len(got) != 1 {
				t.Fatalf("got %+v", got)
			}
			s := got[0]
			if s.Unusual != tt.unusual || !sameStrings(s.Env, tt.env) || !sameStrings(s.Headers, tt.headers) {
				t.Fatalf("got env %v headers %v unusual %v", s.Env, s.Headers, s.Unusual)
			}
		})
	}
}

func TestListServersJSONDisabledAndNumbers(t *testing.T) {
	got, err := ListServers(FormatJSON, []byte(`{"mcpServers":{"a":{"command":"x","disabled":true,"env":{"A_KEY":12345678901234,"B":true}},"b":{"command":"x","enabled":false}}}`))
	if err != nil {
		t.Fatal(err)
	}
	if !got[0].Disabled || got[0].Env["A_KEY"] != "12345678901234" || got[0].Env["B"] != "true" || !got[1].Disabled {
		t.Fatalf("got %+v", got)
	}
}

func sameStrings(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

func TestDecodeJSONExplainsCommentsAndTrailingCommas(t *testing.T) {
	for name, in := range map[string]string{
		"comment":       "{\n// c\n\"a\":1}",
		"object comma":  `{"a":1,}`,
		"array comma":   `{"a":[1,]}`,
		"block comment": `{"a":1 /* x */}`,
	} {
		_, err := ListServers(FormatJSON, []byte(in))
		if err == nil || !strings.Contains(err.Error(), "not plain JSON (comments or trailing commas are not supported)") {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	if _, err := ListServers(FormatJSON, []byte(`{"a":`)); err == nil || strings.Contains(err.Error(), "plain JSON") {
		t.Errorf("plain truncation mislabelled: %v", err)
	}
}
