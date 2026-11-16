package redact

import (
	"encoding/json"
	"strings"
	"testing"
)

// Fake secrets in the shapes real ones take. None of these are live.
var secrets = []string{
	"AKIAIOSFODNN7EXAMPLE",
	"ghp_abcdefghijklmnopqrstuvwxyz0123456789",
	"github_pat_11ABCDEFG0123456789_abcdefghijklmnopqrstuvwxyz",
	"sk-proj-abcdefghijklmnopqrstuvwxyz012345",
	"sk_live_abcdefghijklmnop1234",
	"xoxb-1234567890-abcdefghij",
	"AIzaSyA1234567890abcdefghijklmnopqrstuv",
	"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
	"tgk_ABCDEFGHIJKLMNOPQRSTUVWX",
}

func TestStringRedactsKnownTokenFormats(t *testing.T) {
	for _, s := range secrets {
		got := String("before " + s + " after")
		if strings.Contains(got, s) {
			t.Errorf("String did not redact %q: %q", s, got)
		}
		if !strings.HasPrefix(got, "before ") || !strings.HasSuffix(got, " after") {
			t.Errorf("String damaged surrounding text: %q", got)
		}
	}
}

func TestStringRedactsStructuredSecrets(t *testing.T) {
	cases := map[string]string{
		"bearer header": "Authorization: Bearer abc.def-ghi_jkl",
		"pem":           "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBg\n-----END PRIVATE KEY-----",
		"url userinfo":  "https://alice:hunter2pass@example.com/x",
		"key=value":     "connect with password=hunter2pass now",
		"api_key colon": `api_key: "hunter2pass"`,
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			got := String(in)
			for _, leak := range []string{"hunter2pass", "abc.def-ghi_jkl", "MIIEvQIBADANBg"} {
				if strings.Contains(got, leak) {
					t.Errorf("leaked %q in %q", leak, got)
				}
			}
		})
	}
}

func TestValueRedactsSecretKeysAndDoesNotMutate(t *testing.T) {
	var in map[string]any
	raw := `{"path":"/sandbox/a.txt","api_key":"plainvalue","nested":{"password":"pw123","list":["Bearer tok123456"]},"count":3}`
	if err := json.Unmarshal([]byte(raw), &in); err != nil {
		t.Fatal(err)
	}
	out := Value(in).(map[string]any)
	b, _ := json.Marshal(out)
	for _, leak := range []string{"plainvalue", "pw123", "tok123456"} {
		if strings.Contains(string(b), leak) {
			t.Errorf("redacted value leaks %q: %s", leak, b)
		}
	}
	if out["path"] != "/sandbox/a.txt" || out["count"] != float64(3) {
		t.Errorf("non-secret values changed: %s", b)
	}
	if in["api_key"] != "plainvalue" {
		t.Error("Value mutated its input")
	}
}

func TestHeadersRedactsAuthorization(t *testing.T) {
	h := Headers(map[string][]string{"Authorization": {"Bearer x"}, "Accept": {"application/json"}})
	if h["Authorization"][0] != Marker || h["Accept"][0] != "application/json" {
		t.Errorf("headers = %v", h)
	}
}
