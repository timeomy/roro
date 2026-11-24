package scan

import (
	"slices"
	"strings"

	"github.com/timeomy/roro/internal/clients"
)

// shellSyntax are characters that make a shell line more than a plain
// command: chaining, pipes, redirects, and substitution.
const shellSyntax = ";&|<>`\n"

// launchedByRoro returns the server after "--" for an entry already behind
// `roro wrap`, else the entry as written.
func launchedByRoro(s clients.Server) (string, []string) {
	if !clients.RunsBehindRoro(s.Command, s.Args) {
		return s.Command, s.Args
	}
	if i := slices.Index(s.Args, "--"); i >= 0 && i+1 < len(s.Args) {
		return s.Args[i+1], s.Args[i+2:]
	}
	return s.Command, s.Args
}

// effective returns the command line Roro would actually start: the server
// after `roro wrap`, and the program inside a plain shell launcher such as
// `cmd /c npx -y srv` or `sh -c "npx -y srv"`.
func effective(s clients.Server) (string, []string) {
	cmd, args := launchedByRoro(s)
	if line, ok := shellLine(cmd, args); ok && !hasShellSyntax(line) {
		if fields := strings.Fields(line); len(fields) > 0 {
			return fields[0], fields[1:]
		}
	}
	return cmd, args
}

func hasShellSyntax(line string) bool {
	return strings.ContainsAny(line, shellSyntax) || strings.Contains(line, "$(")
}

// shellLine returns the command line a shell is asked to run. ok is false
// when the command is not a shell or is not given a command line.
func shellLine(command string, args []string) (string, bool) {
	var flags []string
	switch baseCommand(command) {
	case "sh", "bash", "zsh":
		flags = []string{"-c"}
	case "cmd":
		flags = []string{"/c", "/k"}
	case "powershell", "pwsh":
		flags = []string{"-command", "-c"}
	default:
		return "", false
	}
	for i, a := range args {
		if !slices.Contains(flags, strings.ToLower(a)) || (flags[0] == "-c" && a != "-c") {
			continue
		}
		rest := args[i+1:]
		if len(rest) == 0 {
			return "", true
		}
		if flags[0] == "-c" {
			return rest[0], true // later words are $0, $1, not the command
		}
		return strings.Join(rest, " "), true
	}
	return "", false
}

func checkShell(s clients.Server, _ Context) []Finding {
	cmd, args := launchedByRoro(s)
	line, ok := shellLine(cmd, args)
	if !ok || (!hasShellSyntax(line) && strings.TrimSpace(line) != "") {
		return nil
	}
	return []Finding{{Rule: RuleShell, Severity: Low, Title: "Server starts through a shell",
		Detail: "a shell command line is harder to review than a plain command",
		Fix:    "Call the server program directly with its arguments."}}
}
