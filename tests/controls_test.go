package tests

import (
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/timeomy/tollgate/internal/store"
)

func TestKillSwitchAcrossProcesses(t *testing.T) {
	w := newWorkspace(t)
	s := w.connect(bins.echo)
	requireAllowed(t, call(t, s, "echo", map[string]any{"text": "before"}))

	// A separate process flips the switch; the running proxy obeys on the
	// very next call.
	w.tollgate("kill", "--agent", "test-agent", "--reason", "e2e")
	requireBlocked(t, call(t, s, "echo", map[string]any{"text": "during"}), "kill_switch_active")
	if out := w.tollgate("status"); !strings.Contains(out, "kill switch: ON for agent:test-agent") {
		t.Fatalf("status:\n%s", out)
	}

	w.tollgate("resume", "--agent", "test-agent")
	requireAllowed(t, call(t, s, "echo", map[string]any{"text": "after"}))

	w.tollgate("kill")
	requireBlocked(t, call(t, s, "echo", map[string]any{"text": "global"}), "kill_switch_active")
	_ = s.Close()

	// The switch persists: a new proxy process is still blocked.
	s2 := w.connect(bins.echo)
	requireBlocked(t, call(t, s2, "echo", map[string]any{"text": "restart"}), "kill_switch_active")
	w.tollgate("resume")
	requireAllowed(t, call(t, s2, "echo", map[string]any{"text": "resumed"}))
	_ = s2.Close()

	logs := w.tollgate("logs", "--kind", "kill")
	if !strings.Contains(logs, "agent:test-agent") || !strings.Contains(logs, "*") {
		t.Fatalf("kill events missing:\n%s", logs)
	}
	w.tollgate("verify", "--require-sealed")
}

var approvalID = regexp.MustCompile(`=== approval ([0-9a-f]+) ===`)

func TestHumanApprovalViaCLI(t *testing.T) {
	w := newWorkspace(t, func(s string) string { return strings.Replace(s, "timeout: 2s", "timeout: 30s", 1) })
	s := w.connect(bins.exfil)

	// Approve from "another terminal" while the call waits.
	done := make(chan string, 1)
	go func() {
		deadline := time.Now().Add(20 * time.Second)
		for time.Now().Before(deadline) {
			out, _ := w.tollgateErr("approvals", "list")
			if m := approvalID.FindStringSubmatch(out); m != nil {
				if !strings.Contains(out, "tool:     http_post") || !strings.Contains(out, "https://docs.example.org/upload") {
					done <- "approval prompt lacks raw tool/args:\n" + out
					return
				}
				out, err := w.tollgateErr("approvals", "approve", m[1])
				if err != nil {
					done <- out
					return
				}
				done <- ""
				return
			}
			time.Sleep(100 * time.Millisecond)
		}
		done <- "no approval request appeared"
	}()
	res := call(t, s, "http_post", map[string]any{"url": "https://docs.example.org/upload", "body": "weekly summary"})
	if msg := <-done; msg != "" {
		t.Fatal(msg)
	}
	requireAllowed(t, res)
	b, err := os.ReadFile(w.exfil)
	if err != nil || !strings.Contains(string(b), "docs.example.org") {
		t.Fatalf("approved call did not reach upstream: %s %v", b, err)
	}
}

func TestToolPinningBlocksChangedDescription(t *testing.T) {
	w := newWorkspace(t)
	notes := filepath.Join(w.sandbox, "a.txt")
	if err := os.WriteFile(notes, []byte("hello"), 0o600); err != nil {
		t.Fatal(err)
	}
	s := w.connect(bins.exfil)
	if tools, err := s.ListTools(t.Context(), nil); err != nil || len(tools.Tools) != 3 {
		t.Fatalf("first listing: %v %v", tools, err)
	}
	requireAllowed(t, call(t, s, "read_file", map[string]any{"path": notes}))
	_ = s.Close()

	// The server is updated with a poisoned description ("rug pull").
	s2 := w.connect(bins.exfil, "DEMO_POISON=1")
	tools, err := s2.ListTools(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, tl := range tools.Tools {
		if tl.Name == "read_file" {
			t.Fatalf("changed tool still listed: %q", tl.Description)
		}
	}
	requireBlocked(t, call(t, s2, "read_file", map[string]any{"path": notes}), "tool_definition_changed")
	if out := w.tollgate("pins", "list"); !strings.Contains(out, "changed ->") {
		t.Fatalf("pins list:\n%s", out)
	}
	_ = s2.Close()

	// After a human reviews and accepts, the tool works again.
	w.tollgate("pins", "accept", "--server", "demo-exfil-server", "--tool", "read_file")
	s3 := w.connect(bins.exfil, "DEMO_POISON=1")
	requireAllowed(t, call(t, s3, "read_file", map[string]any{"path": notes}))
	_ = s3.Close()
	w.tollgate("verify", "--require-sealed")
}

// copyAndEdit copies a SQLite database and runs statements on the copy.
func copyAndEdit(t *testing.T, src, dst string, stmts []string) {
	t.Helper()
	in, err := os.Open(src)
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(out, in); err != nil {
		t.Fatal(err)
	}
	_ = out.Close()
	db, err := store.Open(t.Context(), dst)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, s := range stmts {
		if _, err := db.Exec(s); err != nil {
			t.Fatalf("%s: %v", s, err)
		}
	}
}
