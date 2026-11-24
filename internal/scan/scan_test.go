package scan

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/timeomy/roro/internal/clients"
)

const fakeGitHubToken = "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789"

func rules(r ServerReport) []string {
	var out []string
	for _, f := range r.Findings {
		out = append(out, f.Rule)
	}
	return out
}

func has(r ServerReport, rule string) bool { return slices.Contains(rules(r), rule) }

func TestServerChecks(t *testing.T) {
	home := "/home/me"
	wrapped := func(inner ...string) clients.Server {
		args := append([]string{"--config", "/c.yaml", "wrap", "--agent", "a", "--server", "s", "--"}, inner...)
		return clients.Server{Name: "s", Command: "/bin/roro", Args: args}
	}
	tests := []struct {
		name   string
		server clients.Server
		want   []string
		absent []string
	}{
		{"token in env", clients.Server{Command: "srv", Env: map[string]string{"GH": fakeGitHubToken}}, []string{RuleSecret, RuleUnprotected}, nil},
		{"secret-named key in plain text", clients.Server{Command: "srv", Env: map[string]string{"API_KEY": "hunter2"}}, []string{RulePlainCred}, []string{RuleSecret}},
		{"env reference is fine", clients.Server{Command: "srv", Env: map[string]string{"API_KEY": "${API_KEY}", "T": "${env:T}", "U": "$U"}}, nil, []string{RulePlainCred, RuleSecret}},
		{"empty secret is fine", clients.Server{Command: "srv", Env: map[string]string{"TOKEN": ""}}, nil, []string{RulePlainCred}},
		{"secret in argument", clients.Server{Command: "srv", Args: []string{"--token=" + fakeGitHubToken}}, []string{RuleSecret}, nil},
		{"plain cred in key=value argument", clients.Server{Command: "srv", Args: []string{"--password=x"}}, []string{RulePlainCred}, nil},
		{"path argument is not a credential", clients.Server{Command: "srv", Args: []string{"/data/tokens"}}, nil, []string{RulePlainCred, RuleSecret}},
		{"bearer header", clients.Server{URL: "https://x.example/mcp", Headers: map[string]string{"Authorization": "Bearer abcdef0123456789abcd"}}, []string{RuleSecret, RuleRemote}, []string{RuleHTTP}},
		{"password in url", clients.Server{URL: "https://u:pw@x.example/mcp"}, []string{RuleSecret}, nil},
		{"plain http remote", clients.Server{URL: "http://x.example/mcp"}, []string{RuleHTTP, RuleRemote}, nil},
		{"plain http localhost ok", clients.Server{URL: "http://127.0.0.1:8080/mcp"}, nil, []string{RuleHTTP}},
		{"plain http localhost name ok", clients.Server{URL: "http://localhost/mcp"}, nil, []string{RuleHTTP}},
		{"bad url", clients.Server{URL: "::not a url"}, []string{RuleHTTP}, nil},
		{"unpinned npx", clients.Server{Command: "npx", Args: []string{"-y", "srv"}}, []string{RuleUnpinned}, nil},
		{"pinned npx", clients.Server{Command: "npx", Args: []string{"-y", "srv@1.0.0"}}, nil, []string{RuleUnpinned}},
		{"root path", clients.Server{Command: "srv", Args: []string{"/"}}, []string{RuleBroadPath}, nil},
		{"home path", clients.Server{Command: "srv", Args: []string{"/home/me/"}}, []string{RuleBroadPath}, nil},
		{"tilde", clients.Server{Command: "srv", Args: []string{"~"}}, []string{RuleBroadPath}, nil},
		{"drive root", clients.Server{Command: "srv", Args: []string{`C:\`}}, []string{RuleBroadPath}, nil},
		{"project path ok", clients.Server{Command: "srv", Args: []string{"/home/me/project"}}, nil, []string{RuleBroadPath}},
		{"privileged container", clients.Server{Command: "docker", Args: []string{"run", "--privileged", "img:1"}}, []string{RulePrivileged}, []string{RuleUnpinned}},
		{"docker socket", clients.Server{Command: "docker", Args: []string{"run", "-v", "/var/run/docker.sock:/var/run/docker.sock", "img:1"}}, []string{RulePrivileged}, nil},
		{"root mount", clients.Server{Command: "docker", Args: []string{"run", "--volume=/:/host", "img:1"}}, []string{RulePrivileged}, nil},
		{"safe mount", clients.Server{Command: "docker", Args: []string{"run", "-v", "/src:/src", "img:1"}}, nil, []string{RulePrivileged}},
		{"host network", clients.Server{Command: "docker", Args: []string{"run", "--network", "host", "img:1"}}, []string{RuleHostNetwork}, nil},
		{"host network =", clients.Server{Command: "podman", Args: []string{"run", "--net=host", "img:1"}}, []string{RuleHostNetwork}, nil},
		{"docker non-run", clients.Server{Command: "docker", Args: []string{"exec", "--privileged"}}, nil, []string{RulePrivileged}},
		{"shell", clients.Server{Command: "bash", Args: []string{"-c", "npx srv | tee log"}}, []string{RuleShell}, nil},
		{"cmd /c", clients.Server{Command: "cmd.exe", Args: []string{"/C", "srv & del x"}}, []string{RuleShell}, nil},
		{"shell script file ok", clients.Server{Command: "bash", Args: []string{"run.sh"}}, nil, []string{RuleShell}},
		{"wrapped is protected", wrapped("npx", "-y", "srv@1.0.0"), nil, []string{RuleUnprotected, RuleUnpinned}},
		{"wrapped inner unpinned", wrapped("npx", "-y", "srv"), []string{RuleUnpinned}, []string{RuleUnprotected}},
		{"wrapped inner broad path", wrapped("srv", "/"), []string{RuleBroadPath}, nil},
		{"unusual", clients.Server{Unusual: true}, []string{RuleUnusual}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := Server(tt.server, Context{Home: home})
			for _, w := range tt.want {
				if !has(r, w) {
					t.Errorf("missing %s; got %v", w, rules(r))
				}
			}
			for _, a := range tt.absent {
				if has(r, a) {
					t.Errorf("unexpected %s; got %v", a, rules(r))
				}
			}
		})
	}
}

func TestFindingsNeverContainSecrets(t *testing.T) {
	s := clients.Server{Command: "srv", Args: []string{"--key=" + fakeGitHubToken}, Env: map[string]string{"GH": fakeGitHubToken},
		URL: "https://u:supersecretpw@x/mcp", Headers: map[string]string{"Authorization": "Bearer abcdef0123456789abcd"}}
	var buf bytes.Buffer
	if err := WriteJSON(&buf, []FileReport{{Servers: []ServerReport{Server(s, Context{})}}}); err != nil {
		t.Fatal(err)
	}
	WriteText(&buf, []FileReport{{Servers: []ServerReport{Server(s, Context{})}}}, Info, Style{})
	for _, secret := range []string{fakeGitHubToken, "supersecretpw", "abcdef0123456789abcd"} {
		if strings.Contains(buf.String(), secret) {
			t.Fatalf("output leaks %q:\n%s", secret, buf.String())
		}
	}
}

func TestFindingsSortedWorstFirst(t *testing.T) {
	r := Server(clients.Server{Command: "npx", Args: []string{"srv", "/"}, Env: map[string]string{"GH": fakeGitHubToken}}, Context{})
	for i := 1; i < len(r.Findings); i++ {
		if r.Findings[i].Severity > r.Findings[i-1].Severity {
			t.Fatalf("not sorted: %v", r.Findings)
		}
	}
	if r.Findings[0].Severity != High {
		t.Fatalf("first finding is %v", r.Findings[0].Severity)
	}
}

func TestFileFixtures(t *testing.T) {
	read := func(name string) []byte {
		data, err := os.ReadFile(filepath.Join("..", "..", "testdata", "scan", name))
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	jsonRep := File(clients.Location{Label: "JSON", Path: "risky.json", Format: clients.FormatJSON}, read("risky.json"), Context{})
	tomlRep := File(clients.Location{Label: "TOML", Path: "codex.toml", Format: clients.FormatCodexTOML}, read("codex.toml"), Context{})
	sum := Summarize([]FileReport{jsonRep, tomlRep})
	if sum.Files != 2 || sum.Servers != 7 {
		t.Fatalf("summary = %+v", sum)
	}
	if sum.Counts["high"] != 5 {
		t.Fatalf("high = %d, want 5 (%+v)", sum.Counts["high"], sum.Counts)
	}
	if sum.Worst != "high" || sum.AtOrAbove(Medium) <= sum.AtOrAbove(High) {
		t.Fatalf("worst/at-or-above wrong: %+v", sum)
	}
	for _, s := range jsonRep.Servers {
		if s.Name == "pinned-safe" && len(s.Findings) != 0 {
			t.Fatalf("pinned-safe should be clean, got %v", rules(s))
		}
	}
	var search ServerReport
	for _, s := range tomlRep.Servers {
		if s.Name == "search" {
			search = s
		}
	}
	if !has(search, RulePlainCred) || !has(search, RuleUnpinned) {
		t.Fatalf("codex search findings = %v", rules(search))
	}
}

func TestFileParseError(t *testing.T) {
	rep := File(clients.Location{Format: clients.FormatJSON}, []byte("{not json"), Context{})
	if rep.Error == "" || len(rep.Servers) != 0 {
		t.Fatalf("got %+v", rep)
	}
}

func TestWriteJSONShape(t *testing.T) {
	rep := File(clients.Location{Client: "cursor", Label: "Cursor", Path: "p", Format: clients.FormatJSON},
		[]byte(`{"mcpServers":{"a":{"command":"npx","args":["srv"]}}}`), Context{})
	var buf bytes.Buffer
	if err := WriteJSON(&buf, []FileReport{rep}); err != nil {
		t.Fatal(err)
	}
	var got struct {
		Version int `json:"version"`
		Files   []struct {
			Client  string `json:"client"`
			Servers []struct {
				Kind     string `json:"kind"`
				Findings []struct {
					Severity string `json:"severity"`
					Rule     string `json:"rule"`
				} `json:"findings"`
			} `json:"servers"`
		} `json:"files"`
		Summary struct {
			Counts map[string]int `json:"counts"`
			Worst  string         `json:"worst"`
		} `json:"summary"`
	}
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Version != 1 || got.Files[0].Client != "cursor" || got.Files[0].Servers[0].Kind != "local" {
		t.Fatalf("shape: %s", buf.String())
	}
	if got.Summary.Worst != "medium" || got.Summary.Counts["medium"] != 1 || got.Summary.Counts["high"] != 0 {
		t.Fatalf("summary: %s", buf.String())
	}
}

func TestWriteText(t *testing.T) {
	reports := []FileReport{
		{Label: "Broken", Path: "b", Error: "could not read this file: bad"},
		{Label: "Empty", Path: "e", Servers: []ServerReport{}},
		{Label: "Cursor", Path: "c", Servers: []ServerReport{
			Server(clients.Server{Name: "risky\x1b[31m", Scope: "/proj", Command: "npx", Args: []string{"srv"}}, Context{}),
			Server(clients.Server{Name: "remote", URL: "https://x/mcp"}, Context{}),
		}},
	}
	var buf bytes.Buffer
	WriteText(&buf, reports, Medium, Style{Clean: func(s string) string { return strings.ReplaceAll(s, "\x1b", "?") }})
	out := buf.String()
	for _, want := range []string{"could not read this file: bad", "no MCP servers", "risky?[31m", "(project /proj)", "MEDIUM", "ok remote", "not shown; use --show"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, "\x1b") {
		t.Fatal("control character from config reached output")
	}

	buf.Reset()
	WriteText(&buf, []FileReport{{Label: "Clean", Servers: []ServerReport{{Name: "x", Findings: []Finding{}}}}}, Low, Style{Color: true})
	if !strings.Contains(buf.String(), "No issues found.") || !strings.Contains(buf.String(), "\x1b[32m") {
		t.Fatalf("clean output:\n%q", buf.String())
	}
}

func TestSeverity(t *testing.T) {
	for _, s := range []Severity{Info, Low, Medium, High} {
		got, ok := ParseSeverity(s.String())
		if !ok || got != s {
			t.Fatalf("round trip %v", s)
		}
		st := Style{Color: true}
		if !strings.Contains(st.sev(s), strings.ToUpper(s.String())) {
			t.Fatalf("label for %v", s)
		}
	}
	if _, ok := ParseSeverity("critical"); ok {
		t.Fatal("unknown severity accepted")
	}
	if lowestShown(Summary{bySev: map[Severity]int{}}) != Info {
		t.Fatal("lowestShown default")
	}
	if count(1, "file") != "1 file" || count(2, "file") != "2 files" {
		t.Fatal("count")
	}
}
