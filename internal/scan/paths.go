package scan

import (
	"fmt"
	"path"
	"regexp"
	"strings"

	"github.com/timeomy/roro/internal/clients"
)

// systemFolders are folders that hold other people's or the system's files.
var systemFolders = map[string]bool{"/Users": true, "/home": true, "/etc": true, "/var": true, "/root": true}

// windowsSystemFolder matches C:/Users and C:/Windows on any drive letter.
var windowsSystemFolder = regexp.MustCompile(`^[a-z]:/(users|windows)$`)

func checkBroadPaths(s clients.Server, ctx Context) []Finding {
	_, args := effective(s)
	var out []Finding
	for _, a := range args {
		value := a
		if strings.HasPrefix(a, "-") {
			if _, v, has := strings.Cut(a, "="); has {
				value = v
			}
		}
		if label := broadPath(value, ctx.Home); label != "" {
			out = append(out, Finding{Rule: RuleBroadPath, Severity: Medium, Title: "Access to a very broad folder",
				Detail: fmt.Sprintf("the server is given %s (%s)", label, a),
				Fix:    "Give it only the project folders it needs."})
		}
	}
	return out
}

func looksWindows(p string) bool {
	return len(p) >= 2 && p[1] == ':' && (p[0]|0x20 >= 'a' && p[0]|0x20 <= 'z')
}

// broadPath names what a path exposes when it is far wider than a project
// folder, or returns "".
func broadPath(a, home string) string {
	switch a {
	case "/", `\`:
		return "the whole disk"
	case "~", "~/", `~\`, "$HOME", "${HOME}", "%USERPROFILE%":
		return "your home folder"
	}
	norm := strings.ReplaceAll(a, `\`, "/")
	trimmed := strings.TrimRight(norm, "/")
	if trimmed == "" {
		return ""
	}
	windows := looksWindows(trimmed)
	if windows {
		trimmed = strings.ToLower(trimmed)
		if len(trimmed) == 2 {
			return "the whole drive"
		}
	}
	if systemFolders[trimmed] || (windows && windowsSystemFolder.MatchString(trimmed)) {
		return "a system or all-users folder"
	}
	if home != "" {
		h := path.Clean(strings.ReplaceAll(home, `\`, "/"))
		p := path.Clean(norm)
		if windows || looksWindows(h) {
			if strings.EqualFold(p, h) {
				return "your home folder"
			}
		} else if p == h {
			return "your home folder"
		}
	}
	return ""
}
