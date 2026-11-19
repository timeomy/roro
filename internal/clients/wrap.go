// Package clients puts Roro in front of the MCP servers that desktop and
// coding assistants already have configured, and takes it out again.
//
// It only rewrites configuration text. Each function takes the file contents
// and returns new contents plus a per-server report; reading, backing up, and
// writing files is the caller's job.
package clients

import (
	"fmt"
	"hash/fnv"
	"path"
	"regexp"
	"strings"
)

// Status says what happened to one configured server.
type Status string

const (
	Wrapped            Status = "protected"
	AlreadyWrapped     Status = "already protected"
	Unwrapped          Status = "restored"
	NotWrapped         Status = "not protected"
	SkippedRemote      Status = "skipped: remote server"
	SkippedUnsupported Status = "skipped: unusual entry"
)

// Result reports on one server entry in a client configuration.
type Result struct {
	Server string
	// Scope is empty for a user-wide entry, or the project path for clients
	// that keep per-project servers.
	Scope  string
	Status Status
}

// Wrapper knows how to launch Roro in front of a server.
type Wrapper struct {
	Roro   string // absolute path to the roro binary
	Config string // absolute path to roro.yaml
}

// WrapCommand returns the command line that runs command behind Roro.
// server must already be a valid server name (see ServerName, Namer).
func (w Wrapper) WrapCommand(agent, server, command string, args []string) (string, []string) {
	out := []string{"--config", w.Config, "wrap", "--agent", agent, "--server", server, "--", command}
	return w.Roro, append(out, args...)
}

func isRoro(command string) bool {
	base := path.Base(strings.ReplaceAll(command, `\`, "/"))
	return strings.TrimSuffix(strings.ToLower(base), ".exe") == "roro"
}

// RunsBehindRoro reports whether a command line already goes through
// `roro wrap`, whether `roro protect` wrote it or the user did by hand.
func RunsBehindRoro(command string, args []string) bool {
	if !isRoro(command) {
		return false
	}
	for _, a := range args {
		if a == "--" {
			return false
		}
		if a == "wrap" {
			return true
		}
	}
	return false
}

// Unwrap returns the original command line of an entry written by
// WrapCommand. ok is false for anything else, including a `roro wrap` line
// the user wrote by hand: unprotect only undoes what protect did.
func Unwrap(command string, args []string) (string, []string, bool) {
	if !isRoro(command) || len(args) < 9 {
		return "", nil, false
	}
	if args[0] != "--config" || args[2] != "wrap" || args[3] != "--agent" || args[5] != "--server" || args[7] != "--" {
		return "", nil, false
	}
	return args[8], append([]string(nil), args[9:]...), true
}

var unsafeServerChars = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

// ServerName turns a client's label for a server into a name Roro accepts
// in policy, pins, and logs.
func ServerName(label string) string {
	name := strings.Trim(unsafeServerChars.ReplaceAllString(label, "-"), "-._")
	if name == "" {
		return "server"
	}
	if len(name) > 64 {
		name = name[:64]
	}
	return name
}

// Namer hands out server names for one configuration file. Two different
// labels never share a name, so their pins, policy, and logs stay separate.
type Namer struct {
	byName map[string]string // name -> label that owns it
}

// Name returns the server name for label.
func (n *Namer) Name(label string) string {
	if n.byName == nil {
		n.byName = map[string]string{}
	}
	name := ServerName(label)
	if owner, taken := n.byName[name]; taken && owner != label {
		h := fnv.New32a()
		_, _ = h.Write([]byte(label))
		suffix := fmt.Sprintf("-%08x", h.Sum32())
		if len(name) > 64-len(suffix) {
			name = name[:64-len(suffix)]
		}
		name += suffix
	}
	n.byName[name] = label
	return name
}
