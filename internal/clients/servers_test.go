package clients

import "testing"

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
	if s := by["local"]; s.Command != "npx" || len(s.Args) != 2 || s.Env["A"] != "1" || len(s.Env) != 1 || s.Unusual || s.Remote() {
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

func TestListServersTOML(t *testing.T) {
	data := []byte("[mcp_servers.a]\ncommand = \"uvx\"\nargs = [\"srv\"]\n\n[mcp_servers.a.env]\nKEY = \"v\" # note\n\"QUOTED\" = 'w'\nbad = [1]\nnoequals\n\n[mcp_servers.r]\nurl = \"https://x/mcp\"\n\n[mcp_servers.ghost.env]\nX = \"1\"\n\n[other]\nk = \"v\"\n[ broken\n")
	got := listTOML(data)
	if len(got) != 2 {
		t.Fatalf("got %+v", got)
	}
	a, r := got[0], got[1]
	if a.Command != "uvx" || a.Env["KEY"] != "v" || a.Env["QUOTED"] != "w" || len(a.Env) != 2 {
		t.Fatalf("a = %+v", a)
	}
	if r.URL != "https://x/mcp" || !r.Remote() {
		t.Fatalf("r = %+v", r)
	}
	other, _ := ListServers(FormatCodexTOML, []byte("mcp_servers.x = { command = \"a\" }\n"))
	if len(other) != 1 || !other[0].Unusual {
		t.Fatalf("dotted form = %+v", other)
	}
}

func TestListServersTOMLHeaders(t *testing.T) {
	data := []byte("[mcp_servers.r]\nurl = \"https://x/mcp\"\nbearer_token_env_var = \"GH\"\n\n[mcp_servers.r.http_headers]\nAuthorization = \"Bearer abc\" # c\n\"X-Key\" = 'k'\n\n[mcp_servers.r.env_http_headers]\nX-Other = \"OTHER_ENV\"\n\n[mcp_servers.r.env]\nA = \"1\"\n\n[mcp_servers.ghost.http_headers]\nH = \"v\"\n")
	got := listTOML(data)
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
