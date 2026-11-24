package scan

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/timeomy/roro/internal/clients"
)

func TestKeyWords(t *testing.T) {
	tests := map[string][]string{
		"API_KEY": {"api", "key"}, "apiKey": {"api", "key"}, "APIKey": {"api", "key"},
		"x-api-key": {"x", "api", "key"}, "a.b": {"a", "b"}, "": nil, "OAuth2Token": {"o", "auth2", "token"},
	}
	for in, want := range tests {
		got := keyWords(in)
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("keyWords(%q) = %v, want %v", in, got, want)
		}
	}
	if namesNotACredential("") {
		t.Error("empty key")
	}
}

func TestCredentialKeyAndArgChecks(t *testing.T) {
	env := func(k, v string) clients.Server { return clients.Server{Command: "srv", Env: map[string]string{k: v}} }
	args := func(a ...string) clients.Server { return clients.Server{Command: "srv", Args: a} }
	tests := []struct {
		name   string
		server clients.Server
		want   []string
		absent []string
	}{
		// 2: whole-word credential names
		{"bypass cache", env("BYPASS_CACHE", "yes"), nil, []string{RulePlainCred}},
		{"passthrough arg", args("--passthrough=yes"), nil, []string{RulePlainCred}},
		{"key env name", env("API_KEY_ENV", "MY_KEY"), nil, []string{RulePlainCred}},
		{"secret name", env("SECRET_NAME", "prod-db"), nil, []string{RulePlainCred}},
		{"password prompt", env("PASSWORD_PROMPT", "Enter it"), nil, []string{RulePlainCred}},
		{"credentials path", env("GOOGLE_APPLICATION_CREDENTIALS", "/home/x/creds.json"), nil, []string{RulePlainCred}},
		{"windows path value", env("TOKEN", `C:\keys\t.txt`), nil, []string{RulePlainCred}},
		{"tilde path value", env("TOKEN", "~/t"), nil, []string{RulePlainCred}},
		{"uppercase variable name value", env("TOKEN", "MY_TOKEN_VAR"), nil, []string{RulePlainCred}},
		{"host and region", env("SESSION_REGION", "eu"), nil, []string{RulePlainCred}},
		{"camelCase apiKey", env("apiKey", "hunter2"), []string{RulePlainCred}, nil},
		{"bare key is not a credential", env("KEY", "hunter2"), nil, []string{RulePlainCred}},
		{"private key", env("PRIVATE_KEY", "hunter2"), []string{RulePlainCred}, nil},
		{"cookie", env("session_cookie", "abc123"), []string{RulePlainCred}, nil},
		// 3: secret as a separate argument
		{"separate token", args("--token", "abc123def456"), []string{RulePlainCred}, nil},
		{"separate password short flag form", args("-password", "hunter2"), []string{RulePlainCred}, nil},
		{"separate pattern secret", args("--api-key", fakeGitHubToken), []string{RuleSecret}, []string{RulePlainCred}},
		{"separate reference", args("--token", "${T}"), nil, []string{RulePlainCred, RuleSecret}},
		{"separate placeholder", args("--token", "<token>"), nil, []string{RulePlainCred}},
		{"separate path", args("--token", "/run/secrets/t"), nil, []string{RulePlainCred}},
		{"separate non-credential flag", args("--name", "hunter2"), nil, []string{RulePlainCred}},
		{"flag then flag", args("--token", "--verbose"), nil, []string{RulePlainCred}},
		{"trailing flag", args("--token"), nil, []string{RulePlainCred}},
		// 5: container flags
		{"privileged true", clients.Server{Command: "docker", Args: []string{"run", "--privileged=true", "img:1"}}, []string{RulePrivileged}, nil},
		{"privileged 1", clients.Server{Command: "docker", Args: []string{"run", "--privileged=1", "img:1"}}, []string{RulePrivileged}, nil},
		{"privileged false", clients.Server{Command: "docker", Args: []string{"run", "--privileged=false", "img:1"}}, nil, []string{RulePrivileged}},
		{"seccomp unconfined spaced", clients.Server{Command: "docker", Args: []string{"run", "--security-opt", "seccomp=unconfined", "img:1"}}, []string{RulePrivileged}, nil},
		{"apparmor unconfined equals", clients.Server{Command: "docker", Args: []string{"run", "--security-opt=apparmor=unconfined", "img:1"}}, []string{RulePrivileged}, nil},
		{"seccomp colon form", clients.Server{Command: "docker", Args: []string{"run", "--security-opt", "seccomp:unconfined", "img:1"}}, []string{RulePrivileged}, nil},
		{"security-opt label ok", clients.Server{Command: "docker", Args: []string{"run", "--security-opt", "no-new-privileges", "img:1"}}, nil, []string{RulePrivileged}},
		{"userns host equals", clients.Server{Command: "docker", Args: []string{"run", "--userns=host", "img:1"}}, []string{RulePrivileged}, nil},
		{"userns host spaced", clients.Server{Command: "docker", Args: []string{"run", "--userns", "host", "img:1"}}, []string{RulePrivileged}, nil},
		{"userns other ok", clients.Server{Command: "docker", Args: []string{"run", "--userns", "keep-id", "img:1"}}, nil, []string{RulePrivileged}},
		// 4: unknown flag means the image is not guessed
		{"unknown docker flag skips P001", clients.Server{Command: "docker", Args: []string{"run", "--made-up", "thing", "acme/mcp"}}, nil, []string{RuleUnpinned}},
		// 7 and 8: pins and noise
		{"npm major only unpinned", clients.Server{Command: "npx", Args: []string{"srv@1"}}, []string{RuleUnpinned}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := Server(tt.server, Context{})
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

func TestSeparateArgumentIsNotReportedTwice(t *testing.T) {
	r := Server(clients.Server{Command: "srv", Args: []string{"--token", fakeGitHubToken}}, Context{})
	n := 0
	for _, f := range r.Findings {
		if f.Rule == RuleSecret {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("S001 reported %d times: %+v", n, r.Findings)
	}
}

func TestUnprotectedIsInfo(t *testing.T) {
	r := Server(clients.Server{Command: "srv"}, Context{})
	if len(r.Findings) != 1 || r.Findings[0].Rule != RuleUnprotected || r.Findings[0].Severity != Info {
		t.Fatalf("findings = %+v", r.Findings)
	}
}

func TestSummaryDoesNotCountUnreadableFiles(t *testing.T) {
	bad := FileReport{Label: "Bad", Path: "b", Error: "could not read this file: x", Servers: []ServerReport{}}
	good := FileReport{Label: "Good", Path: "g", Servers: []ServerReport{{Name: "a", Findings: []Finding{}}}}
	tests := []struct {
		name    string
		reports []FileReport
		want    []string
		absent  []string
		files   int
	}{
		{"only unreadable", []FileReport{bad}, []string{"Scanned 0 servers in 0 files. 1 file could not be read."}, []string{"No issues found."}, 0},
		{"mixed", []FileReport{bad, good}, []string{"Scanned 1 server in 1 file. 1 file could not be read."}, []string{"No issues found."}, 1},
		{"all fine", []FileReport{good}, []string{"No issues found."}, []string{"could not be read."}, 1},
		{"unreadable and findings", []FileReport{bad, {Label: "F", Servers: []ServerReport{{Name: "s", Findings: []Finding{{Rule: "R", Severity: High}}}}}},
			[]string{"1 file could not be read. Found 1 high."}, []string{"No issues found."}, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sum := Summarize(tt.reports)
			if sum.Files != tt.files {
				t.Errorf("Files = %d, want %d", sum.Files, tt.files)
			}
			var buf bytes.Buffer
			WriteText(&buf, tt.reports, Low, Style{})
			for _, w := range tt.want {
				if !strings.Contains(buf.String(), w) {
					t.Errorf("missing %q in:\n%s", w, buf.String())
				}
			}
			for _, a := range tt.absent {
				if strings.Contains(buf.String(), a) {
					t.Errorf("unexpected %q in:\n%s", a, buf.String())
				}
			}
		})
	}
}

func TestWriteJSONEscapesInvisibleRunes(t *testing.T) {
	hostile := "evil\u202e\u2066\u200e\u200f\u0085\u009b[31mname\u2069\u202a"
	rep := []FileReport{{Label: "L", Path: "p", Servers: []ServerReport{{Name: hostile, Findings: []Finding{}}}}}
	var buf bytes.Buffer
	if err := WriteJSON(&buf, rep); err != nil {
		t.Fatal(err)
	}
	for _, r := range buf.String() {
		if (r >= 0x202A && r <= 0x202E) || (r >= 0x2066 && r <= 0x2069) || r == 0x200E || r == 0x200F || (r >= 0x80 && r <= 0x9F) {
			t.Fatalf("raw rune %U in output:\n%s", r, buf.String())
		}
	}
	if !strings.Contains(buf.String(), `\u202e`) || !strings.Contains(buf.String(), `\u009b`) {
		t.Fatalf("escapes missing:\n%s", buf.String())
	}
	var doc struct {
		Files []struct {
			Servers []struct {
				Name string `json:"name"`
			} `json:"servers"`
		} `json:"files"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil || doc.Files[0].Servers[0].Name != hostile {
		t.Fatalf("round trip (%v): %+v", err, doc)
	}
	buf.Reset()
	if err := WriteJSON(&buf, []FileReport{{Label: "caf\u00e9 \u4e2d"}}); err != nil || !strings.Contains(buf.String(), "caf\u00e9 \u4e2d") {
		t.Fatalf("ordinary non-ASCII must stay readable: %v %s", err, buf.String())
	}
}
