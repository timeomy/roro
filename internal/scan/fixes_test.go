package scan

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/timeomy/roro/internal/clients"
)

func TestServerChecksHardening(t *testing.T) {
	env := func(k, v string) map[string]string { return map[string]string{k: v} }
	docker := func(args ...string) clients.Server {
		return clients.Server{Command: "docker", Args: append([]string{"run"}, args...)}
	}
	tests := []struct {
		name   string
		server clients.Server
		want   []string
		absent []string
	}{
		// 2: env references in headers
		{"bearer env reference", clients.Server{URL: "https://x/mcp", Headers: env("Authorization", "Bearer ${GITHUB_TOKEN}")}, nil, []string{RuleSecret, RulePlainCred}},
		{"basic env reference", clients.Server{URL: "https://x/mcp", Headers: env("Authorization", "basic $CREDS")}, nil, []string{RuleSecret, RulePlainCred}},
		{"token scheme mustache", clients.Server{URL: "https://x/mcp", Headers: env("Authorization", "Token {{ghToken}}")}, nil, []string{RuleSecret, RulePlainCred}},
		{"reference beside a real secret", clients.Server{Command: "srv", Env: env("X", "${A}"+fakeGitHubToken)}, []string{RuleSecret}, nil},
		{"bearer with real value", clients.Server{URL: "https://x/mcp", Headers: env("Authorization", "Bearer abcdef0123456789abcd")}, []string{RuleSecret}, nil},
		// 4: S002 false positives
		{"max tokens number", clients.Server{Command: "srv", Env: env("MAX_TOKENS", "4096")}, nil, []string{RulePlainCred}},
		{"token limit number", clients.Server{Command: "srv", Env: env("TOKEN_LIMIT", "5")}, nil, []string{RulePlainCred}},
		{"boolean value", clients.Server{Command: "srv", Env: env("USE_API_KEY", "true")}, nil, []string{RulePlainCred}},
		{"your placeholder", clients.Server{Command: "srv", Env: env("API_KEY", "YOUR_API_KEY_HERE")}, nil, []string{RulePlainCred}},
		{"angle placeholder", clients.Server{Command: "srv", Env: env("X_TOKEN", "<token>")}, nil, []string{RulePlainCred}},
		{"changeme placeholder", clients.Server{Command: "srv", Env: env("PASSWORD", "ChangeMe")}, nil, []string{RulePlainCred}},
		{"min prefix key", clients.Server{Command: "srv", Env: env("MIN_SECRET_LEN", "abc")}, nil, []string{RulePlainCred}},
		{"key file suffix", clients.Server{Command: "srv", Env: env("API_KEY_FILE", "k.txt")}, nil, []string{RulePlainCred}},
		{"dash suffix", clients.Server{Command: "srv", Args: []string{"--token-url=abc"}}, nil, []string{RulePlainCred}},
		{"real plain value still flagged", clients.Server{Command: "srv", Env: env("API_KEY", "hunter2")}, []string{RulePlainCred}, nil},
		{"pattern match unchanged for numeric-named key", clients.Server{Command: "srv", Env: env("MAX_TOKENS", fakeGitHubToken)}, []string{RuleSecret}, nil},
		// 6: shell launchers
		{"cmd /c npx unpinned", clients.Server{Command: "cmd", Args: []string{"/c", "npx", "-y", "@modelcontextprotocol/server-memory"}}, []string{RuleUnpinned}, []string{RuleShell}},
		{"cmd /k pinned", clients.Server{Command: "cmd.exe", Args: []string{"/K", "npx", "-y", "srv@1.0.0"}}, nil, []string{RuleUnpinned, RuleShell}},
		{"sh -c npx", clients.Server{Command: "sh", Args: []string{"-c", "npx -y srv"}}, []string{RuleUnpinned}, []string{RuleShell}},
		{"powershell -Command", clients.Server{Command: "powershell", Args: []string{"-Command", "npx -y srv"}}, []string{RuleUnpinned}, []string{RuleShell}},
		{"pwsh -c broad path", clients.Server{Command: "pwsh", Args: []string{"-c", "srv", "/"}}, []string{RuleBroadPath}, []string{RuleShell}},
		{"sh -c docker privileged", clients.Server{Command: "sh", Args: []string{"-c", "docker run --privileged img:1"}}, []string{RulePrivileged}, []string{RuleShell}},
		{"sh -c with chain keeps X001", clients.Server{Command: "sh", Args: []string{"-c", "cd /tmp; srv"}}, []string{RuleShell}, nil},
		{"sh -c substitution keeps X001", clients.Server{Command: "sh", Args: []string{"-c", "srv $(whoami)"}}, []string{RuleShell}, nil},
		{"sh -c empty keeps X001", clients.Server{Command: "sh", Args: []string{"-c"}}, []string{RuleShell}, nil},
		// 7: docker flags are not images
		{"tmpfs value skipped", docker("--tmpfs", "/tmp", "img"), []string{RuleUnpinned}, nil},
		{"restart value skipped", docker("--restart", "always", "--ulimit", "nofile=1", "--shm-size", "1g", "img:1"), nil, []string{RuleUnpinned}},
		{"flag equals form", docker("--restart=always", "--pid=private", "img:1"), nil, []string{RuleUnpinned}},
		{"pinned image after many flags", docker("--log-driver", "none", "--gpus", "all", "--volumes-from", "x", "--expose", "80", "img:1"), nil, []string{RuleUnpinned}},
		// 8: container exposure
		{"mount bind root", docker("--mount", "type=bind,src=/,dst=/h", "img:1"), []string{RulePrivileged}, nil},
		{"mount source key", docker("--mount=type=bind,source=/var/run/docker.sock,target=/s", "img:1"), []string{RulePrivileged}, nil},
		{"mount home", docker("--mount", "type=bind,src=/home/me,dst=/h", "img:1"), []string{RulePrivileged}, nil},
		{"mount safe", docker("--mount", "type=bind,src=/home/me/p,dst=/h", "img:1"), nil, []string{RulePrivileged}},
		{"volume home", docker("-v", "/home/me:/h", "img:1"), []string{RulePrivileged}, nil},
		{"volume windows home", docker("-v", `C:\Users:/h`, "img:1"), []string{RulePrivileged}, nil},
		{"pid host", docker("--pid=host", "img:1"), []string{RuleHostNetwork}, nil},
		{"pid host spaced", docker("--pid", "host", "img:1"), []string{RuleHostNetwork}, nil},
		{"ipc host", docker("--ipc=host", "img:1"), []string{RuleHostNetwork}, nil},
		{"ipc private", docker("--ipc", "private", "img:1"), nil, []string{RuleHostNetwork}},
		{"cap SYS_ADMIN", docker("--cap-add", "SYS_ADMIN", "img:1"), []string{RulePrivileged}, nil},
		{"cap ALL equals", docker("--cap-add=ALL", "img:1"), []string{RulePrivileged}, nil},
		{"cap prefixed", docker("--cap-add=cap_sys_admin", "img:1"), []string{RulePrivileged}, nil},
		{"cap harmless", docker("--cap-add", "NET_BIND_SERVICE", "img:1"), nil, []string{RulePrivileged}},
		// 10: broad paths
		{"/Users", clients.Server{Command: "srv", Args: []string{"/Users"}}, []string{RuleBroadPath}, nil},
		{"/etc slash", clients.Server{Command: "srv", Args: []string{"/etc/"}}, []string{RuleBroadPath}, nil},
		{"/var", clients.Server{Command: "srv", Args: []string{"/var"}}, []string{RuleBroadPath}, nil},
		{"/root", clients.Server{Command: "srv", Args: []string{"/root"}}, []string{RuleBroadPath}, nil},
		{"windows users back", clients.Server{Command: "srv", Args: []string{`C:\Users\`}}, []string{RuleBroadPath}, nil},
		{"windows lower drive", clients.Server{Command: "srv", Args: []string{"d:/windows"}}, []string{RuleBroadPath}, nil},
		{"windows home case", clients.Server{Command: "srv", Args: []string{`c:\users\ME`}}, []string{RuleBroadPath}, nil},
		{"/etc/nginx fine", clients.Server{Command: "srv", Args: []string{"/etc/nginx"}}, nil, []string{RuleBroadPath}},
		{"/users lower on unix fine", clients.Server{Command: "srv", Args: []string{"/users"}}, nil, []string{RuleBroadPath}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			home := "/home/me"
			if strings.Contains(tt.name, "windows home") {
				home = `C:\Users\me`
			}
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

func TestMountFindingNamesHome(t *testing.T) {
	r := Server(clients.Server{Command: "docker", Args: []string{"run", "-v", "~:/h", "img:1"}}, Context{})
	for _, f := range r.Findings {
		if f.Rule == RulePrivileged && f.Severity == High && strings.Contains(f.Detail, "home folder") {
			return
		}
	}
	t.Fatalf("no high home-folder mount finding: %+v", r.Findings)
}

func TestPlainCredFixNamesSanitisedVariable(t *testing.T) {
	r := Server(clients.Server{URL: "https://x/mcp", Headers: map[string]string{"X-API-KEY": "hunter2"}}, Context{})
	for _, f := range r.Findings {
		if f.Rule == RulePlainCred {
			if !strings.Contains(f.Fix, "${X_API_KEY}") || strings.Contains(f.Fix, "${X-API-KEY}") {
				t.Fatalf("fix = %q", f.Fix)
			}
			return
		}
	}
	t.Fatalf("no S002: %+v", r.Findings)
}

func TestSummaryWorst(t *testing.T) {
	if got := Summarize(nil).Worst; got != "none" {
		t.Fatalf("empty worst = %q", got)
	}
	clean := []FileReport{{Servers: []ServerReport{{Name: "a", Findings: []Finding{}}}}}
	if got := Summarize(clean).Worst; got != "none" {
		t.Fatalf("clean worst = %q", got)
	}
	info := []FileReport{{Servers: []ServerReport{{Findings: []Finding{{Severity: Info}}}}}}
	if got := Summarize(info).Worst; got != "info" {
		t.Fatalf("info worst = %q", got)
	}
	var buf bytes.Buffer
	if err := WriteJSON(&buf, clean); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Summary struct {
			Worst string `json:"worst"`
		} `json:"summary"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil || doc.Summary.Worst != "none" {
		t.Fatalf("json (%v): %s", err, buf.String())
	}
}

func TestHiddenFindingsAreNotOk(t *testing.T) {
	rep := []FileReport{{Label: "L", Path: "p", Servers: []ServerReport{
		{Name: "busy", Findings: []Finding{{Rule: "R1", Severity: Medium}, {Rule: "R2", Severity: Low}, {Rule: "R3", Severity: Info}}},
		{Name: "quiet", Findings: []Finding{{Rule: "R3", Severity: Info}}},
		{Name: "clean", Findings: []Finding{}},
	}}}
	var buf bytes.Buffer
	WriteText(&buf, rep, High, Style{})
	out := buf.String()
	if strings.Contains(out, "ok busy") || !strings.Contains(out, "busy  2 below high not shown") {
		t.Errorf("busy server mislabelled:\n%s", out)
	}
	if !strings.Contains(out, "ok quiet") || !strings.Contains(out, "ok clean") {
		t.Errorf("clean servers not ok:\n%s", out)
	}
}

func TestCodexHeaderSecretIsFound(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "testdata", "scan", "codex_headers.toml"))
	if err != nil {
		t.Fatal(err)
	}
	rep := File(clients.Location{Format: clients.FormatCodexTOML}, data, Context{})
	if len(rep.Servers) != 1 {
		t.Fatalf("servers = %+v", rep.Servers)
	}
	r := rep.Servers[0]
	var n int
	for _, f := range r.Findings {
		if f.Rule == RulePlainCred && strings.Contains(f.Detail, "header X-Api-Key") {
			n++
		}
	}
	if n != 1 || has(r, RuleSecret) || len(r.Findings) != 2 {
		t.Fatalf("findings = %v (S002 on header: %d)", rules(r), n)
	}
}
