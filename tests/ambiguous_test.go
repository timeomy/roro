package tests

import (
	"bufio"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// TestAmbiguousParamsRefusedEndToEnd sends raw JSON-RPC through the real
// binary: params a lenient parser could read as a harmless tool must be
// refused before they reach the upstream, and an ordinary call on the same
// connection must still work.
func TestAmbiguousParamsRefusedEndToEnd(t *testing.T) {
	w := newWorkspace(t)
	cmd := exec.Command(bins.tollgate, "--config", w.config, "wrap", "--agent", "test-agent", "--", bins.exfil)
	cmd.Env = append(os.Environ(), "DEMO_EXFIL_LOG="+w.exfil)
	cmd.Stderr = testWriter{t}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stdin.Close(); _ = cmd.Wait() })

	lines := make(chan map[string]any, 16)
	go func() {
		sc := bufio.NewScanner(stdout)
		sc.Buffer(make([]byte, 1<<20), 1<<20)
		for sc.Scan() {
			var m map[string]any
			if json.Unmarshal(sc.Bytes(), &m) == nil {
				lines <- m
			}
		}
		close(lines)
	}()
	send := func(s string) {
		t.Helper()
		if _, err := io.WriteString(stdin, s+"\n"); err != nil {
			t.Fatal(err)
		}
	}
	recv := func(id float64) map[string]any {
		t.Helper()
		timeout := time.After(15 * time.Second)
		for {
			select {
			case m, ok := <-lines:
				if !ok {
					t.Fatal("tollgate closed stdout")
				}
				if m["id"] == id {
					return m
				}
			case <-timeout:
				t.Fatalf("no response for id %v", id)
			}
		}
	}

	send(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"raw","version":"0"}}}`)
	recv(1)
	send(`{"jsonrpc":"2.0","method":"notifications/initialized"}`)

	attacks := []string{
		`{"name":"exfiltrate","arguments":{"data":"x"},"NAME":"echo"}`,
		`{"name":"exfiltrate","name":"get_time"}`,
		`{"name":"read_file","arguments":{"path":"` + w.sandbox + `/x","PATH":"/etc/passwd"}}`,
	}
	for i, params := range attacks {
		id := float64(10 + i)
		b, _ := json.Marshal(id)
		send(`{"jsonrpc":"2.0","id":` + string(b) + `,"method":"tools/call","params":` + params + `}`)
		resp := recv(id)
		errObj, _ := resp["error"].(map[string]any)
		if errObj == nil || errObj["code"] != float64(-32602) || !strings.Contains(errObj["message"].(string), "rejected") {
			t.Fatalf("attack %d: want invalid params, got %v", i, resp)
		}
	}
	send(`{"jsonrpc":"2.0","id":20,"method":"tools/list"}`)
	recv(20)
	send(`{"jsonrpc":"2.0","id":21,"method":"tools/call","params":{"name":"exfiltrate","arguments":{"data":"x"}}}`)
	if res, _ := recv(21)["result"].(map[string]any); res == nil || res["isError"] != true {
		t.Fatalf("plain exfiltrate call should be a denial result, got %v", res)
	}
	_ = stdin.Close()
	if b, err := os.ReadFile(w.exfil); err == nil {
		t.Fatalf("an attack reached the upstream server:\n%s", b)
	}
}
