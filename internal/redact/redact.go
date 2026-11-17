// Package redact removes obvious secrets from values before they are written
// to the audit log, shown in an approval prompt, or exported to telemetry.
//
// Redaction is best-effort pattern matching. It catches common token formats
// and secret-looking keys; it cannot recognise every secret. Tollgate stores a
// hash of the redacted arguments, never the raw arguments.
package redact

import (
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"
)

// Marker replaces redacted content.
const Marker = "[REDACTED]"

// secretKey matches object keys whose values are treated as secrets.
var secretKey = regexp.MustCompile(`(?i)(pass(word|wd|phrase)?|secret|token|api[_-]?key|apikey|authori[sz]ation|bearer|private[_-]?key|credential|cookie|session[_-]?id|access[_-]?key|client[_-]?secret|signature)`)

type rule struct {
	re   *regexp.Regexp
	repl string
}

// rules are applied in order to every string value.
var rules = []rule{
	{regexp.MustCompile(`(?i)\bbearer\s+[A-Za-z0-9\-._~+/]+=*`), "Bearer " + Marker},
	{regexp.MustCompile(`(?i)\bbasic\s+[A-Za-z0-9+/]{8,}=*`), "Basic " + Marker},
	{regexp.MustCompile(`\b(AKIA|ASIA)[0-9A-Z]{16}\b`), "[REDACTED:aws_key]"},
	{regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{30,}\b`), "[REDACTED:github_token]"},
	{regexp.MustCompile(`\bgithub_pat_[A-Za-z0-9_]{22,}\b`), "[REDACTED:github_token]"},
	{regexp.MustCompile(`\bsk-[A-Za-z0-9_\-]{20,}`), "[REDACTED:api_key]"},
	{regexp.MustCompile(`\b[rs]k_(live|test)_[A-Za-z0-9]{16,}\b`), "[REDACTED:api_key]"},
	{regexp.MustCompile(`\bxox[abprs]-[A-Za-z0-9-]{10,}`), "[REDACTED:slack_token]"},
	{regexp.MustCompile(`\bAIza[0-9A-Za-z\-_]{35}\b`), "[REDACTED:google_api_key]"},
	{regexp.MustCompile(`\btgk_[A-Za-z0-9]{16,}\b`), "[REDACTED:tollgate_token]"},
	{regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}`), "[REDACTED:jwt]"},
	// scheme://user:password@host
	{regexp.MustCompile(`(://[^/\s:@]+:)[^/\s@]+@`), "${1}" + Marker + "@"},
	// key=value / key: value inside free text
	{regexp.MustCompile(`(?i)\b(api[_-]?key|password|passwd|secret|token|access[_-]?token|client[_-]?secret)(\s*[:=]\s*["']?)[^\s"'&,;]+`), "${1}${2}" + Marker},
}

// pemBlock matches a PEM block. The body may only hold base64 and PEM header
// characters, so attacker-supplied BEGIN/END markers cannot swallow arbitrary
// text (shell metacharacters, quotes, braces) and hide it from an approver.
var pemBlock = regexp.MustCompile(`-----BEGIN [A-Z0-9 ]{1,64}-----[A-Za-z0-9+/=\s:,.\-]*?-----END [A-Z0-9 ]{1,64}-----`)

// String redacts secrets inside a string.
func String(s string) string {
	s = pemBlock.ReplaceAllStringFunc(s, func(m string) string {
		return fmt.Sprintf("[REDACTED:pem %d bytes]", len(m))
	})
	for _, r := range rules {
		s = r.re.ReplaceAllString(s, r.repl)
	}
	return s
}

// IsSecretKey reports whether an object key names a secret.
func IsSecretKey(key string) bool { return secretKey.MatchString(key) }

// Value returns a redacted deep copy of a JSON-like value (the result of
// json.Unmarshal into any). The input is never modified.
//
// Everything under a secret-looking key is masked, including nested objects
// and arrays. Keys are redacted too, since a secret can be sent as a key.
func Value(v any) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for _, k := range slices.Sorted(maps.Keys(t)) { // sorted: collision suffixes are stable
			val := t[k]
			key := uniqueKey(out, String(k))
			if IsSecretKey(k) && val != nil {
				out[key] = Marker
				continue
			}
			out[key] = Value(val)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, val := range t {
			out[i] = Value(val)
		}
		return out
	case string:
		return String(t)
	default:
		return v
	}
}

// uniqueKey keeps two keys distinct when redaction maps both to the same
// text, so no value is silently dropped from the copy.
func uniqueKey(m map[string]any, key string) string {
	if _, taken := m[key]; !taken {
		return key
	}
	for i := 2; ; i++ {
		k := fmt.Sprintf("%s#%d", key, i)
		if _, taken := m[k]; !taken {
			return k
		}
	}
}

// Contains reports whether s holds redaction output.
func Contains(s string) bool { return strings.Contains(s, "[REDACTED") }

// Headers redacts sensitive HTTP header values in a copy of h.
func Headers(h map[string][]string) map[string][]string {
	out := make(map[string][]string, len(h))
	for k, vals := range h {
		if IsSecretKey(k) || strings.EqualFold(k, "X-Api-Key") {
			out[k] = []string{Marker}
			continue
		}
		cp := make([]string, len(vals))
		for i, v := range vals {
			cp[i] = String(v)
		}
		out[k] = cp
	}
	return out
}
