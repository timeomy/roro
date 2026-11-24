package scan

import (
	"fmt"
	"net"
	"net/url"
	"slices"
	"strings"

	"github.com/timeomy/roro/internal/clients"
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
	RuleDisabled    = "RORO-G004"
)

type check func(clients.Server, Context) []Finding

var checks = []check{
	checkSecrets, checkTransport, checkUnpinned, checkBroadPaths,
	checkContainer, checkShell, checkProtection,
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

func checkProtection(s clients.Server, _ Context) []Finding {
	switch {
	case s.Unusual:
		return []Finding{{Rule: RuleUnusual, Severity: Info, Title: "Entry not fully read",
			Detail: "it is written in a form Roro does not read completely", Fix: "Review this entry by hand."}}
	case s.Command == "" && s.URL != "":
		return []Finding{{Rule: RuleRemote, Severity: Info, Title: "Remote server, not checked by Roro",
			Detail: "roro protect wraps local servers only", Fix: "Review what this server can do with the access you give it."}}
	case !clients.RunsBehindRoro(s.Command, s.Args):
		return []Finding{{Rule: RuleUnprotected, Severity: Info, Title: "Tool calls are not checked",
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
