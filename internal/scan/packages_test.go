package scan

import "testing"

func TestPackageLaunch(t *testing.T) {
	tests := []struct {
		name    string
		command string
		args    []string
		spec    string
		pinned  bool
		ok      bool
	}{
		{"npx unpinned", "npx", []string{"-y", "@scope/server"}, "@scope/server", false, true},
		{"npx scoped pinned", "npx", []string{"-y", "@scope/server@1.2.3"}, "@scope/server@1.2.3", true, true},
		{"npx latest tag", "npx", []string{"server@latest"}, "server@latest", false, true},
		{"npx caret range", "npx", []string{"server@^1.2.0"}, "server@^1.2.0", false, true},
		{"npx --package", "npx", []string{"--package", "server@2.0.0", "run-it"}, "server@2.0.0", true, true},
		{"npx --package=", "npx", []string{"--package=server", "run-it"}, "server", false, true},
		{"npx skips valued flag", "npx", []string{"--registry", "https://r.example", "srv@1.0.0"}, "srv@1.0.0", true, true},
		{"npx after --", "npx", []string{"-y", "--", "srv"}, "srv", false, true},
		{"npx local path", "npx", []string{"./server.js"}, "", false, false},
		{"npx git without commit", "npx", []string{"github:acme/srv"}, "github:acme/srv", false, true},
		{"npx git with commit", "npx", []string{"git+https://x/y.git#0123456789abcdef0123456789abcdef01234567"}, "git+https://x/y.git#0123456789abcdef0123456789abcdef01234567", true, true},
		{"npx windows exe", `C:\node\npx.cmd`, []string{"srv"}, "srv", false, true},
		{"npx only flags", "npx", []string{"-y"}, "", false, false},
		{"bunx", "bunx", []string{"srv@0.1.0"}, "srv@0.1.0", true, true},
		{"pnpm dlx", "pnpm", []string{"dlx", "srv"}, "srv", false, true},
		{"npm exec", "npm", []string{"exec", "srv@3.1.0"}, "srv@3.1.0", true, true},
		{"npm install is not a launch", "npm", []string{"install"}, "", false, false},
		{"uvx unpinned", "uvx", []string{"mcp-server-fetch"}, "mcp-server-fetch", false, true},
		{"uvx pinned ==", "uvx", []string{"mcp-server-fetch==2025.4.7"}, "mcp-server-fetch==2025.4.7", true, true},
		{"uvx pinned @", "uvx", []string{"srv@1.0"}, "srv@1.0", true, true},
		{"uvx --from", "uvx", []string{"--from", "pkg==1.0.0", "cmd"}, "pkg==1.0.0", true, true},
		{"uvx --from=", "uvx", []string{"--from=pkg", "cmd"}, "pkg", false, true},
		{"uvx skips --python", "uvx", []string{"--python", "3.12", "srv"}, "srv", false, true},
		{"uv tool run", "uv", []string{"tool", "run", "srv"}, "srv", false, true},
		{"pipx run", "pipx", []string{"run", "srv==1.0.0"}, "srv==1.0.0", true, true},
		{"docker untagged", "docker", []string{"run", "-i", "--rm", "-e", "X=1", "ghcr.io/acme/mcp"}, "ghcr.io/acme/mcp", false, true},
		{"docker latest", "docker", []string{"run", "acme/mcp:latest"}, "acme/mcp:latest", false, true},
		{"docker tag", "docker", []string{"run", "acme/mcp:1.4"}, "acme/mcp:1.4", true, true},
		{"docker registry port", "docker", []string{"run", "localhost:5000/mcp"}, "localhost:5000/mcp", false, true},
		{"docker digest", "podman", []string{"run", "acme/mcp@sha256:abc"}, "acme/mcp@sha256:abc", true, true},
		{"docker no image", "docker", []string{"run", "-i"}, "", false, false},
		{"docker ps", "docker", []string{"ps"}, "", false, false},
		{"npm major only is a range", "npx", []string{"srv@1"}, "srv@1", false, true},
		{"npm minor only is a range", "npx", []string{"srv@1.2"}, "srv@1.2", false, true},
		{"npm prerelease pinned", "npx", []string{"srv@1.2.3-rc.1"}, "srv@1.2.3-rc.1", true, true},
		{"uvx == x.y", "uvx", []string{"srv==1.2"}, "srv==1.2", true, true},
		{"uvx == major only", "uvx", []string{"srv==1"}, "srv==1", false, true},
		{"uvx from git commit", "uvx", []string{"--from", "git+https://x/y.git@0123456789abcdef0123456789abcdef01234567", "cmd"}, "git+https://x/y.git@0123456789abcdef0123456789abcdef01234567", true, true},
		{"uvx from git branch", "uvx", []string{"--from", "git+https://x/y.git@main", "cmd"}, "git+https://x/y.git@main", false, true},
		{"uvx from git no ref", "uvx", []string{"--from", "git+https://x/y.git", "cmd"}, "git+https://x/y.git", false, true},
		{"pipx direct reference commit", "pipx", []string{"run", "pkg @ git+https://x/y.git@0123456789abcdef0123456789abcdef01234567"}, "pkg @ git+https://x/y.git@0123456789abcdef0123456789abcdef01234567", true, true},
		{"docker many value flags", "docker", []string{"run", "--pids-limit", "5", "--sysctl", "a=1", "--ip", "1.2.3.4", "-c", "2", "-a", "stdout", "--health-retries", "3", "acme/mcp:1"}, "acme/mcp:1", true, true},
		{"docker unknown flag then word is not guessed", "docker", []string{"run", "--made-up", "thing", "acme/mcp"}, "", false, false},
		{"docker unknown flag then flag", "docker", []string{"run", "--made-up", "-i", "acme/mcp"}, "acme/mcp", false, true},
		{"docker unknown flag equals", "docker", []string{"run", "--made-up=1", "acme/mcp"}, "acme/mcp", false, true},
		{"docker bool cluster", "docker", []string{"run", "-dit", "--init", "--read-only", "acme/mcp"}, "acme/mcp", false, true},
		{"plain binary", "/usr/local/bin/server", nil, "", false, false},
		{"node script", "node", []string{"server.js"}, "", false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l, ok := packageLaunch(tt.command, tt.args)
			if ok != tt.ok {
				t.Fatalf("ok = %v, want %v (%+v)", ok, tt.ok, l)
			}
			if !ok {
				return
			}
			if l.spec != tt.spec || l.pinned != tt.pinned {
				t.Fatalf("got spec %q pinned %v, want %q %v", l.spec, l.pinned, tt.spec, tt.pinned)
			}
		})
	}
}

func TestIsLocalPath(t *testing.T) {
	for _, p := range []string{"./a", "/abs", "~/x", "file:x", `C:\x`, "C:/x"} {
		if !isLocalPath(p) {
			t.Errorf("%q should be local", p)
		}
	}
	for _, p := range []string{"pkg", "@s/p", "C:"} {
		if isLocalPath(p) {
			t.Errorf("%q should not be local", p)
		}
	}
}
