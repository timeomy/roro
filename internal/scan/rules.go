package scan

import (
	"fmt"
	"net"
	"net/url"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/timeomy/roro/internal/clients"
	"github.com/timeomy/roro/internal/redact"
)

// Rule ids are stable: scripts and CI configs may match on them.
const (
	RuleSecret      = "RORO-S001"
	RulePlainCred   = "RORO-S002"
	RuleHTTP        = "RORO-N001"
	RuleUnpinned    = "RORO-P001"
	RuleBroadPath   = "RORO-F001"
	RulePrivileged  = "RORO-C001"
	RuleHostNetwork = "RORO-C002"
	RuleShell       = "RORO-X001"
	RuleUnprotected = "RORO-G001"
	RuleRemote      = "RORO-G002"
	RuleUnusual     = "RORO-G003"
)

type check func(clients.Server, Context) []Finding

var checks = []check{
	checkSecrets, checkTransport, checkUnpinned, checkBroadPaths,
	checkContainer, checkShell, checkProtection,
}

// effective returns the command line Roro would actually start: for an
// entry already behind `roro wrap`, the server after "--".
func effective(s clients.Server) (string, []string) {
	if !clients.RunsBehindRoro(s.Command, s.Args) {
		return s.Command, s.Args
	}
	if i := slices.Index(s.Args, "--"); i >= 0 && i+1 < len(s.Args) {
		return s.Args[i+1], s.Args[i+2:]
	}
	return s.Command, s.Args
}

// redactedKind matches the label inside redaction output, e.g. aws_key.
var redactedKind = regexp.MustCompile(`\[REDACTED:?([a-z_]*)`)

// envReference matches values that point at a variable instead of holding
// the secret: ${VAR}, ${env:VAR}, $VAR, {{VAR}}.
var envReference = regexp.MustCompile(`^(\$\{[^}]+\}|\$[A-Za-z_][A-Za-z0-9_]*|\{\{[^}]+\}\})$`)

func checkSecrets(s clients.Server, _ Context) []Finding {
	var out []Finding
	look := func(where, key, value string) {
		if value == "" || envReference.MatchString(strings.TrimSpace(value)) {
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
				Detail: fmt.Sprintf("%s looks like a %s", where, kindName),
				Fix:    "Rotate it, then load it from an environment variable or your OS keychain. Anything that can read this file can read the secret.",
			})
			return
		}
		if key != "" && redact.IsSecretKey(key) {
			out = append(out, Finding{
				Rule: RulePlainCred, Severity: Medium,
				Title:  "Credential stored as plain text",
				Detail: fmt.Sprintf("%s holds a value written directly in the file", where),
				Fix:    "Reference an environment variable instead, for example ${" + strings.ToUpper(key) + "}, if your AI tool supports it.",
			})
		}
	}
	for _, k := range sortedKeys(s.Env) {
		look("env "+k, k, s.Env[k])
	}
	for _, k := range sortedKeys(s.Headers) {
		look("header "+k, k, s.Headers[k])
	}
	for i, a := range s.Args {
		key, value, hasValue := strings.Cut(strings.TrimLeft(a, "-"), "=")
		if !hasValue {
			key, value = "", a
		}
		look(fmt.Sprintf("argument %d", i+1), key, value)
	}
	look("url", "", s.URL)
	return out
}

func checkTransport(s clients.Server, _ Context) []Finding {
	if s.URL == "" {
		return nil
	}
	u, err := url.Parse(s.URL)
	if err != nil || u.Host == "" {
		return []Finding{{Rule: RuleHTTP, Severity: Low, Title: "Server address could not be read",
			Detail: "the url is not a valid web address", Fix: "Check the address by hand."}}
	}
	if strings.EqualFold(u.Scheme, "http") && !isLoopback(u.Hostname()) {
		return []Finding{{Rule: RuleHTTP, Severity: High, Title: "Remote server over plain HTTP",
			Detail: "calls and their arguments to " + u.Hostname() + " are sent unencrypted",
			Fix:    "Use the server's https:// address."}}
	}
	return nil
}

func isLoopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func checkUnpinned(s clients.Server, _ Context) []Finding {
	cmd, args := effective(s)
	l, ok := packageLaunch(cmd, args)
	if !ok || l.pinned {
		return nil
	}
	return []Finding{{Rule: RuleUnpinned, Severity: Medium, Title: "Package not pinned to a version",
		Detail: fmt.Sprintf("%s runs %q, so a new release runs the next time your AI tool starts", l.tool, l.spec),
		Fix:    "Pin an exact version (name@1.2.3, name==1.2.3, or image:tag / image@sha256:...) and update on purpose."}}
}

func checkBroadPaths(s clients.Server, ctx Context) []Finding {
	_, args := effective(s)
	var out []Finding
	for _, a := range args {
		if label := broadPath(a, ctx.Home); label != "" {
			out = append(out, Finding{Rule: RuleBroadPath, Severity: Medium, Title: "Access to a very broad folder",
				Detail: fmt.Sprintf("the server is given %s (%s)", label, a),
				Fix:    "Give it only the project folders it needs."})
		}
	}
	return out
}

func broadPath(a, home string) string {
	switch a {
	case "/", `\`:
		return "the whole disk"
	case "~", "~/", `~\`, "$HOME", "${HOME}", "%USERPROFILE%":
		return "your home folder"
	}
	if len(a) == 3 && a[1] == ':' && (a[2] == '\\' || a[2] == '/') {
		return "the whole drive"
	}
	if home != "" && filepath.Clean(a) == filepath.Clean(home) {
		return "your home folder"
	}
	return ""
}

func checkContainer(s clients.Server, _ Context) []Finding {
	cmd, args := effective(s)
	if b := baseCommand(cmd); (b != "docker" && b != "podman") || len(args) == 0 || args[0] != "run" {
		return nil
	}
	var out []Finding
	for i, a := range args {
		next := ""
		if i+1 < len(args) {
			next = args[i+1]
		}
		switch {
		case a == "--privileged":
			out = append(out, Finding{Rule: RulePrivileged, Severity: High, Title: "Container runs privileged",
				Detail: "--privileged gives the server near full control of the host", Fix: "Remove --privileged."})
		case (a == "-v" || a == "--volume") && dangerousMount(next) != "":
			out = append(out, mountFinding(dangerousMount(next)))
		case strings.HasPrefix(a, "--volume=") && dangerousMount(strings.TrimPrefix(a, "--volume=")) != "":
			out = append(out, mountFinding(dangerousMount(strings.TrimPrefix(a, "--volume="))))
		case (a == "--network" || a == "--net") && next == "host", a == "--network=host", a == "--net=host":
			out = append(out, Finding{Rule: RuleHostNetwork, Severity: Low, Title: "Container shares the host network",
				Detail: "it can reach services bound to localhost on your machine", Fix: "Drop --network host unless the server needs it."})
		}
	}
	return out
}

// dangerousMount names what a volume spec exposes, or returns "".
func dangerousMount(spec string) string {
	src, _, _ := strings.Cut(spec, ":")
	switch {
	case src == "/":
		return "the host's whole disk"
	case strings.HasSuffix(src, "docker.sock"):
		return "the Docker socket, which controls every container on the host"
	}
	return ""
}

func mountFinding(what string) Finding {
	return Finding{Rule: RulePrivileged, Severity: High, Title: "Container mounts the host",
		Detail: "it mounts " + what, Fix: "Mount only the folders the server needs."}
}

func checkShell(s clients.Server, _ Context) []Finding {
	cmd, args := effective(s)
	switch baseCommand(cmd) {
	case "sh", "bash", "zsh", "cmd", "powershell", "pwsh":
	default:
		return nil
	}
	for _, a := range args {
		if a == "-c" || strings.EqualFold(a, "/c") || strings.EqualFold(a, "-command") {
			return []Finding{{Rule: RuleShell, Severity: Low, Title: "Server starts through a shell",
				Detail: "a shell command line is harder to review than a plain command",
				Fix:    "Call the server program directly with its arguments."}}
		}
	}
	return nil
}

func checkProtection(s clients.Server, _ Context) []Finding {
	switch {
	case s.Unusual:
		return []Finding{{Rule: RuleUnusual, Severity: Info, Title: "Entry not fully read",
			Detail: "it is written in a form Roro does not read completely", Fix: "Review this entry by hand."}}
	case s.Command == "" && s.URL != "":
		return []Finding{{Rule: RuleRemote, Severity: Info, Title: "Remote server, not checked by Roro",
			Detail: "roro protect wraps local servers only", Fix: "Review what this server can do with the access you give it."}}
	case !clients.RunsBehindRoro(s.Command, s.Args):
		return []Finding{{Rule: RuleUnprotected, Severity: Low, Title: "Tool calls are not checked",
			Detail: "nothing checks or logs what your agent asks this server to do",
			Fix:    "Run `roro protect` to put Roro in front of it."}}
	}
	return nil
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}
