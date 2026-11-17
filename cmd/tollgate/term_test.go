package main

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/timeomy/tollgate/internal/approval"
)

func TestCleanEscapesTerminalControls(t *testing.T) {
	for _, in := range []string{"echo\napproved", "x\x1b[2Ky", "x\u009b2Ky", "a‮b", "a\rb", "a\x7fb"} {
		got := clean(in)
		for _, r := range got {
			if r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) || r == 0x202e {
				t.Errorf("clean(%q) = %q still holds control %U", in, got, r)
			}
		}
	}
	if got := clean(strings.Repeat("a", 1000)); len([]rune(got)) > maxFieldLen+1 {
		t.Errorf("clean did not cap length: %d", len(got))
	}
	if got := cleanMultiline("{\n  \"a\": 1\n}"); got != "{\n  \"a\": 1\n}" {
		t.Errorf("cleanMultiline changed JSON: %q", got)
	}
}

func TestPrintRequestCannotForgeLines(t *testing.T) {
	var b bytes.Buffer
	printRequest(&b, approval.Request{
		ID: "abc", Agent: "bot", Server: "demo", Tool: "evil\nexpires:  never\x1b[1A",
		ArgsJSON: "{\n  \"cmd\": \"[REDACTED:pem 40 bytes]\"\n}", Expires: time.Now().Add(time.Minute),
	})
	out := b.String()
	if strings.Count(out, "\nexpires:") != 1 || strings.Contains(out, "\x1b") {
		t.Fatalf("tool name forged prompt lines:\n%s", out)
	}
	if !strings.Contains(out, "WARNING") {
		t.Fatalf("no redaction warning:\n%s", out)
	}
}
