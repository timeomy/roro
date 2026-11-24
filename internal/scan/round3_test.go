package scan

import (
	"bytes"
	"strings"
	"testing"

	"github.com/timeomy/roro/internal/clients"
)

func TestDisabledServerOnlyChecksSecrets(t *testing.T) {
	r := Server(clients.Server{Command: "npx", Args: []string{"srv", "/"}, Disabled: true,
		Env: map[string]string{"GH": fakeGitHubToken}}, Context{})
	if !r.Disabled || !has(r, RuleDisabled) || !has(r, RuleSecret) {
		t.Fatalf("got %v", rules(r))
	}
	for _, rule := range []string{RuleUnpinned, RuleBroadPath, RuleUnprotected} {
		if has(r, rule) {
			t.Fatalf("disabled server got %s", rule)
		}
	}
}

func TestBroadPathInsideFlagValue(t *testing.T) {
	for _, a := range []string{"--root=/", "--dir=~", "-d=/etc"} {
		if !has(Server(clients.Server{Command: "srv", Args: []string{a}}, Context{}), RuleBroadPath) {
			t.Errorf("%s not flagged", a)
		}
	}
	if has(Server(clients.Server{Command: "srv", Args: []string{"--root=/srv/project"}}, Context{}), RuleBroadPath) {
		t.Error("project folder flagged")
	}
}

func TestSecretDetailUsesRightArticle(t *testing.T) {
	r := Server(clients.Server{Command: "srv", Env: map[string]string{"K": "AKIAIOSFODNN7EXAMPLE"}}, Context{})
	if !strings.Contains(r.Findings[0].Detail, "looks like an aws key") {
		t.Fatalf("detail = %q", r.Findings[0].Detail)
	}
	if withArticle("github token") != "a github token" {
		t.Fatal("a")
	}
}

func TestSummaryLineHasNoTrailingSpace(t *testing.T) {
	var buf bytes.Buffer
	WriteText(&buf, []FileReport{{Label: "x", Error: "could not read this file: bad"}}, Low, Style{})
	for _, line := range strings.Split(buf.String(), "\n") {
		if strings.HasSuffix(line, " ") {
			t.Fatalf("trailing space in %q", line)
		}
	}
	if !strings.Contains(buf.String(), "1 file could not be read.") || strings.Contains(buf.String(), "No issues found") {
		t.Fatalf("output:\n%s", buf.String())
	}
}

func TestNonObjectServerListIsReported(t *testing.T) {
	rep := File(clients.Location{Format: clients.FormatJSON}, []byte(`{"mcpServers":[1]}`), Context{})
	if len(rep.Servers) != 1 || !has(rep.Servers[0], RuleUnusual) {
		t.Fatalf("got %+v", rep)
	}
}

func TestCodexMultiLineSecretIsFound(t *testing.T) {
	data := "[mcp_servers.a]\ncommand = \"x\"\n[mcp_servers.a.env]\nGITHUB_TOKEN = \"\"\"" + fakeGitHubToken + "\"\"\"\n"
	rep := File(clients.Location{Format: clients.FormatCodexTOML}, []byte(data), Context{})
	if rep.Error != "" || !has(rep.Servers[0], RuleSecret) {
		t.Fatalf("got %+v", rep)
	}
	bad := File(clients.Location{Format: clients.FormatCodexTOML}, []byte("[mcp_servers.a]\nenv = {K=\"v\"\n"), Context{})
	if bad.Error == "" {
		t.Fatal("broken TOML accepted")
	}
}
