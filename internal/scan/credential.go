package scan

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/timeomy/roro/internal/clients"
	"github.com/timeomy/roro/internal/redact"
)

// redactedKind matches the label inside redaction output, e.g. aws_key.
var redactedKind = regexp.MustCompile(`\[REDACTED:?([a-z_]*)`)

// envReference matches values that point at a variable instead of holding
// the secret: ${VAR}, ${env:VAR}, $VAR, {{VAR}}.
var envReference = regexp.MustCompile(`^(\$\{[^}]+\}|\$[A-Za-z_][A-Za-z0-9_]*|\{\{[^}]+\}\})$`)

// embeddedReference finds a variable reference anywhere in a value.
var embeddedReference = regexp.MustCompile(`\$\{[^}]+\}|\$[A-Za-z_][A-Za-z0-9_]*|\{\{[^}]+\}\}`)

// authScheme is the word in front of a token in an Authorization header.
var authScheme = regexp.MustCompile(`(?i)^(bearer|basic|token)\s+`)

// placeholderValue matches text that stands in for a real credential.
var placeholderValue = regexp.MustCompile(`(?i)^(<.*>|your[_-].*|xxx+|changeme|\*+|placeholder|todo)$`)

// storedElsewhere matches values that name a file or another variable.
var storedElsewhere = regexp.MustCompile(`^(/|~|\./|\.\./|[A-Za-z]:[\\/]|[A-Z][A-Z0-9_]+$)`)

// argFlag matches a command-line flag such as --token or -k.
var argFlag = regexp.MustCompile(`^--?[A-Za-z][\w-]*$`)

// isReference reports whether a value points at a variable rather than
// holding a secret. An "Authorization" scheme word is ignored, and text
// around the reference must not look like a secret itself.
func isReference(value string) bool {
	rest := strings.TrimSpace(authScheme.ReplaceAllString(strings.TrimSpace(value), ""))
	if envReference.MatchString(rest) {
		return true
	}
	return embeddedReference.MatchString(rest) && redact.String(rest) == rest
}

// notACredential reports whether a credential-named setting plainly holds
// something else: a number, a flag, a placeholder, a path, the name of
// another variable, or a limit.
func notACredential(key, value string) bool {
	v := strings.TrimSpace(value)
	if _, err := strconv.ParseFloat(v, 64); err == nil {
		return true
	}
	if strings.EqualFold(v, "true") || strings.EqualFold(v, "false") ||
		placeholderValue.MatchString(v) || storedElsewhere.MatchString(v) {
		return true
	}
	return namesNotACredential(key)
}

// variableName turns a setting name into an environment variable name.
func variableName(key string) string {
	return strings.Map(func(r rune) rune {
		if r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' {
			return r
		}
		return '_'
	}, strings.ToUpper(key))
}

func checkSecrets(s clients.Server, _ Context) []Finding {
	var out []Finding
	look := func(where, key, value string) {
		if value == "" || isReference(value) {
			return
		}
		if red := redact.String(value); red != value {
			kindName := "secret"
			if m := redactedKind.FindStringSubmatch(red); m != nil && m[1] != "" {
				kindName = strings.ReplaceAll(m[1], "_", " ")
			} else if strings.Contains(red, "Bearer "+redact.Marker) {
				kindName = "bearer token"
			}
			out = append(out, Finding{
				Rule: RuleSecret, Severity: High,
				Title:  "Secret written in the config file",
				Detail: fmt.Sprintf("%s looks like %s", where, withArticle(kindName)),
				Fix:    "Rotate it, then load it from an environment variable or your OS keychain. Anything that can read this file can read the secret.",
			})
			return
		}
		if key != "" && isCredentialKey(key) && !notACredential(key, value) {
			out = append(out, Finding{
				Rule: RulePlainCred, Severity: Medium,
				Title:  "Credential stored as plain text",
				Detail: fmt.Sprintf("%s holds a value written directly in the file", where),
				Fix:    "Reference an environment variable instead, for example ${" + variableName(key) + "}, if your AI tool supports it.",
			})
		}
	}
	for _, k := range sortedKeys(s.Env) {
		look("env "+k, k, s.Env[k])
	}
	for _, k := range sortedKeys(s.Headers) {
		look("header "+k, k, s.Headers[k])
	}
	skip := -1
	for i, a := range s.Args {
		if i == skip {
			continue
		}
		if name := strings.TrimLeft(a, "-"); argFlag.MatchString(a) && isCredentialKey(name) &&
			i+1 < len(s.Args) && !argFlag.MatchString(s.Args[i+1]) {
			look(fmt.Sprintf("argument %d", i+2), name, s.Args[i+1])
			skip = i + 1
			continue
		}
		key, value, hasValue := strings.Cut(strings.TrimLeft(a, "-"), "=")
		if !hasValue {
			key, value = "", a
		}
		look(fmt.Sprintf("argument %d", i+1), key, value)
	}
	look("url", "", s.URL)
	return out
}

// withArticle puts "a" or "an" before a noun phrase.
func withArticle(noun string) string {
	if noun != "" && strings.ContainsRune("aeiouAEIOU", rune(noun[0])) {
		return "an " + noun
	}
	return "a " + noun
}
