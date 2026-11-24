package scan

import (
	"strings"

	"github.com/timeomy/roro/internal/clients"
)

func checkContainer(s clients.Server, ctx Context) []Finding {
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
		flag, inline, hasInline := strings.Cut(a, "=")
		value := next
		if hasInline {
			value = inline
		}
		switch {
		case flag == "--privileged":
			if hasInline && !truthy(inline) {
				break
			}
			out = append(out, Finding{Rule: RulePrivileged, Severity: High, Title: "Container runs privileged",
				Detail: "--privileged gives the server near full control of the host", Fix: "Remove --privileged."})
		case flag == "-v" || flag == "--volume":
			if what := dangerousMount(volumeSource(value), ctx.Home); what != "" {
				out = append(out, mountFinding(what))
			}
		case flag == "--mount":
			if what := dangerousMount(mountSource(value), ctx.Home); what != "" {
				out = append(out, mountFinding(what))
			}
		case flag == "--network" || flag == "--net":
			if value == "host" {
				out = append(out, hostShare("network", "it can reach services bound to localhost on your machine", "--network host"))
			}
		case flag == "--pid" || flag == "--ipc":
			if value == "host" {
				out = append(out, hostShare(strings.TrimPrefix(flag, "--"), "it can see or reach processes on your machine", flag+" host"))
			}
		case flag == "--security-opt":
			if o := strings.ReplaceAll(strings.ToLower(value), ":", "="); o == "seccomp=unconfined" || o == "apparmor=unconfined" {
				out = append(out, Finding{Rule: RulePrivileged, Severity: High, Title: "Container turns off a security filter",
					Detail: "--security-opt " + o + " removes a protection that limits what the server can do on the host",
					Fix:    "Remove --security-opt " + o + "."})
			}
		case flag == "--userns":
			if value == "host" {
				out = append(out, Finding{Rule: RulePrivileged, Severity: High, Title: "Container shares the host user namespace",
					Detail: "--userns host means root in the container is root on your machine",
					Fix:    "Remove --userns host."})
			}
		case flag == "--cap-add":
			if c := strings.ToUpper(strings.TrimPrefix(strings.ToUpper(value), "CAP_")); c == "SYS_ADMIN" || c == "ALL" {
				out = append(out, Finding{Rule: RulePrivileged, Severity: High, Title: "Container gets broad host powers",
					Detail: "--cap-add " + c + " lets the server act almost like an administrator", Fix: "Remove --cap-add " + c + "."})
			}
		}
	}
	return out
}

func truthy(v string) bool {
	switch strings.ToLower(v) {
	case "true", "1", "yes", "on":
		return true
	}
	return false
}

func hostShare(what, detail, flag string) Finding {
	return Finding{Rule: RuleHostNetwork, Severity: Low, Title: "Container shares the host " + what,
		Detail: detail, Fix: "Drop " + flag + " unless the server needs it."}
}

// volumeSource returns the host side of a -v spec such as /src:/dst:ro.
func volumeSource(spec string) string {
	if looksWindows(spec) && len(spec) > 2 && (spec[2] == '\\' || spec[2] == '/') {
		src, _, _ := strings.Cut(spec[2:], ":")
		return spec[:2] + src
	}
	src, _, _ := strings.Cut(spec, ":")
	return src
}

// mountSource returns the source of a --mount spec such as
// type=bind,src=/,dst=/host.
func mountSource(spec string) string {
	for _, part := range strings.Split(spec, ",") {
		if k, v, ok := strings.Cut(part, "="); ok && (k == "src" || k == "source") {
			return v
		}
	}
	return ""
}

// dangerousMount names what a mount source exposes, or returns "".
func dangerousMount(src, home string) string {
	switch {
	case src == "":
		return ""
	case src == "/":
		return "the host's whole disk"
	case strings.HasSuffix(src, "docker.sock"):
		return "the Docker socket, which controls every container on the host"
	}
	return broadPath(src, home)
}

func mountFinding(what string) Finding {
	return Finding{Rule: RulePrivileged, Severity: High, Title: "Container mounts the host",
		Detail: "it mounts " + what, Fix: "Mount only the folders the server needs."}
}
