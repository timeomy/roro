package identity

import (
	"strings"
	"testing"
)

func TestValidate(t *testing.T) {
	for _, ok := range []string{"cursor", "research-bot", "a", "bot.v2_x"} {
		if err := (Agent{Name: ok}).Validate(); err != nil {
			t.Errorf("%q rejected: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "Cursor", "-x", "has space", strings.Repeat("a", 65), "a/b", `a"b`} {
		if err := (Agent{Name: bad}).Validate(); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if (Agent{Name: "cursor"}).String() != "agent::cursor" {
		t.Error("display form changed")
	}
}

func TestTokenDirectory(t *testing.T) {
	tok, digest, err := NewToken()
	if err != nil || !strings.HasPrefix(tok, TokenPrefix) || HashToken(tok) != digest {
		t.Fatalf("NewToken = %q %q %v", tok, digest, err)
	}
	other, otherDigest, _ := NewToken()
	d, err := NewDirectory([]TokenEntry{
		{Agent: Agent{Name: "a"}, Digest: digest},
		{Agent: Agent{Name: "b"}, Digest: strings.ToUpper(otherDigest)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if a, ok := d.Lookup(tok); !ok || a.Name != "a" {
		t.Errorf("Lookup(a) = %v %v", a, ok)
	}
	if a, ok := d.Lookup(other); !ok || a.Name != "b" {
		t.Errorf("Lookup(b) = %v %v", a, ok)
	}
	for _, bad := range []string{"", "tgk_wrong", digest} {
		if _, ok := d.Lookup(bad); ok {
			t.Errorf("Lookup(%q) succeeded", bad)
		}
	}
	if _, err := NewDirectory([]TokenEntry{{Agent: Agent{Name: "a"}, Digest: "short"}}); err == nil {
		t.Error("short digest accepted")
	}
	if _, err := NewDirectory([]TokenEntry{{Agent: Agent{Name: "a"}, Digest: digest}, {Agent: Agent{Name: "b"}, Digest: digest}}); err == nil {
		t.Error("shared digest accepted")
	}
}
