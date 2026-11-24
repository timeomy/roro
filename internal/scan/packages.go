package scan

import (
	"path"
	"regexp"
	"strings"
)

// fullVersion is an npm version that names one release: x.y.z, with an
// optional prerelease or build part. npm treats @1 and @1.2 as ranges.
var fullVersion = regexp.MustCompile(`^v?\d+\.\d+\.\d+([-+][0-9A-Za-z.\-+]+)?$`)

// pyVersion is a Python version for an exact pin: x.y or x.y.z.
var pyVersion = regexp.MustCompile(`^v?\d+\.\d+(\.\d+)?([-+.][0-9A-Za-z.\-+]+)?$`)

// commitHash is a full git commit id.
var commitHash = regexp.MustCompile(`^[0-9a-f]{40}$`)

// launch describes a command that downloads and runs a package.
type launch struct {
	tool   string // npx, uvx, docker, ...
	spec   string // the package or image as written
	pinned bool
}

// baseCommand returns the lower-case program name without directory or .exe/.cmd.
func baseCommand(command string) string {
	b := strings.ToLower(path.Base(strings.ReplaceAll(command, `\`, "/")))
	for _, ext := range []string{".exe", ".cmd", ".bat"} {
		b = strings.TrimSuffix(b, ext)
	}
	return b
}

// packageLaunch works out which package a command line downloads and runs.
// ok is false for anything that is not a package runner, or a runner
// pointed at a local path.
func packageLaunch(command string, args []string) (launch, bool) {
	switch tool := baseCommand(command); tool {
	case "npx", "bunx":
		return npmLike(tool, args)
	case "pnpm", "yarn", "npm", "bun":
		if len(args) > 0 && (args[0] == "dlx" || args[0] == "exec" || args[0] == "x") {
			return npmLike(tool+" "+args[0], args[1:])
		}
	case "uvx":
		return pythonLike(tool, args)
	case "uv":
		if len(args) > 1 && args[0] == "tool" && args[1] == "run" {
			return pythonLike("uv tool run", args[2:])
		}
	case "pipx":
		if len(args) > 0 && args[0] == "run" {
			return pythonLike("pipx run", args[1:])
		}
	case "docker", "podman":
		if len(args) > 0 && args[0] == "run" {
			return containerLike(tool, args[1:])
		}
	}
	return launch{}, false
}

// npmValueFlags take a separate value.
var npmValueFlags = map[string]bool{"-p": true, "--package": true, "-c": true, "--call": true, "--registry": true, "--cache": true}

func npmLike(tool string, args []string) (launch, bool) {
	spec := ""
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			if spec == "" && i+1 < len(args) {
				spec = args[i+1]
			}
			break
		}
		if name, val, has := strings.Cut(a, "="); has && (name == "--package" || name == "-p") {
			spec = val
			break
		}
		if npmValueFlags[a] {
			if (a == "-p" || a == "--package") && i+1 < len(args) {
				spec = args[i+1]
				break
			}
			i++
			continue
		}
		if strings.HasPrefix(a, "-") {
			continue
		}
		spec = a
		break
	}
	if spec == "" || isLocalPath(spec) {
		return launch{}, false
	}
	return launch{tool: tool, spec: spec, pinned: npmPinned(spec)}, true
}

func npmPinned(spec string) bool {
	if strings.HasPrefix(spec, "git") || strings.Contains(spec, "://") {
		// git or URL specs are pinned only by a full commit hash.
		_, ref, has := strings.Cut(spec, "#")
		return has && commitHash.MatchString(ref)
	}
	name := spec
	if strings.HasPrefix(name, "@") {
		name = name[1:]
	}
	_, version, has := strings.Cut(name, "@")
	return has && fullVersion.MatchString(version)
}

var pyValueFlags = map[string]bool{"--with": true, "--python": true, "-p": true, "--index-url": true, "--spec": true}

func pythonLike(tool string, args []string) (launch, bool) {
	spec := ""
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--from" && i+1 < len(args) {
			spec = args[i+1]
			break
		}
		if v, ok := strings.CutPrefix(a, "--from="); ok {
			spec = v
			break
		}
		if pyValueFlags[a] {
			i++
			continue
		}
		if strings.HasPrefix(a, "-") {
			continue
		}
		spec = a
		break
	}
	if spec == "" || isLocalPath(spec) {
		return launch{}, false
	}
	return launch{tool: tool, spec: spec, pinned: pythonPinned(spec)}, true
}

func pythonPinned(spec string) bool {
	if strings.Contains(spec, "git+") || strings.Contains(spec, "://") {
		// git or URL specs are pinned only by a full commit hash.
		i := strings.LastIndex(spec, "@")
		return i >= 0 && commitHash.MatchString(spec[i+1:])
	}
	if _, v, has := strings.Cut(spec, "=="); has {
		return pyVersion.MatchString(v)
	}
	if _, v, has := strings.Cut(spec, "@"); has {
		return pyVersion.MatchString(v)
	}
	return false
}

// containerValueFlags take a separate value in `docker run`.
var containerValueFlags = map[string]bool{
	"-e": true, "--env": true, "--env-file": true, "-v": true, "--volume": true, "--mount": true,
	"-p": true, "--publish": true, "--name": true, "--network": true, "--net": true,
	"-w": true, "--workdir": true, "-u": true, "--user": true, "--entrypoint": true,
	"-l": true, "--label": true, "--platform": true, "--pull": true, "--cpus": true,
	"-m": true, "--memory": true, "--add-host": true, "--cap-add": true, "--cap-drop": true,
	"--device": true, "--dns": true, "-h": true, "--hostname": true, "--security-opt": true,
	"--tmpfs": true, "--pid": true, "--ipc": true, "--log-driver": true, "--log-opt": true,
	"--ulimit": true, "--restart": true, "--group-add": true, "--shm-size": true,
	"--stop-signal": true, "--health-cmd": true, "--gpus": true, "--runtime": true,
	"--cidfile": true, "--memory-swap": true, "--cpuset-cpus": true, "--label-file": true,
	"--network-alias": true, "--uts": true, "--userns": true, "--cgroupns": true,
	"--expose": true, "--link": true, "--volumes-from": true,
	"--pids-limit": true, "--sysctl": true, "--storage-opt": true, "--mac-address": true,
	"--ip": true, "--ip6": true, "--dns-search": true, "--dns-option": true, "-c": true,
	"--cpu-shares": true, "--cpu-period": true, "--cpu-quota": true, "--device-cgroup-rule": true,
	"--annotation": true, "--stop-timeout": true, "--oom-score-adj": true, "--blkio-weight": true,
	"--memory-reservation": true, "--kernel-memory": true, "--isolation": true,
	"--health-interval": true, "--health-retries": true, "--health-timeout": true,
	"--health-start-period": true, "--domainname": true, "--link-local-ip": true,
	"--volume-driver": true, "--attach": true, "-a": true,
}

// containerBoolFlags take no value.
var containerBoolFlags = map[string]bool{
	"-i": true, "-t": true, "-d": true, "--rm": true, "--init": true, "--read-only": true,
	"--privileged": true, "--interactive": true, "--tty": true, "--detach": true,
	"--no-healthcheck": true, "--oom-kill-disable": true, "--sig-proxy": true,
	"--disable-content-trust": true, "--publish-all": true, "-P": true, "-q": true, "--quiet": true,
}

// shortBoolCluster matches combined boolean short flags such as -it or -dit.
var shortBoolCluster = regexp.MustCompile(`^-[itdqP]+$`)

func containerLike(tool string, args []string) (launch, bool) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		if containerValueFlags[a] {
			i++
			continue
		}
		if strings.HasPrefix(a, "-") {
			if strings.Contains(a, "=") || containerBoolFlags[a] || shortBoolCluster.MatchString(a) {
				continue
			}
			// An unknown flag followed by a word: that word may be its value
			// or the image. Do not guess.
			if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				return launch{}, false
			}
			continue
		}
		return launch{tool: tool, spec: a, pinned: imagePinned(a)}, true
	}
	return launch{}, false
}

func imagePinned(image string) bool {
	if strings.Contains(image, "@sha256:") {
		return true
	}
	last := image[strings.LastIndex(image, "/")+1:]
	_, tag, has := strings.Cut(last, ":")
	return has && tag != "" && tag != "latest"
}

func isLocalPath(spec string) bool {
	return strings.HasPrefix(spec, ".") || strings.HasPrefix(spec, "/") || strings.HasPrefix(spec, "~") ||
		strings.HasPrefix(spec, "file:") || (len(spec) > 2 && spec[1] == ':' && (spec[2] == '\\' || spec[2] == '/'))
}
