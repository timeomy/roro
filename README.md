<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/logo-dark.svg">
    <img src="assets/logo.svg" alt="Roro" width="220">
  </picture>
</p>

<p align="center">
  <b>A safety check between your AI tools and what they can do.</b><br>
  It logs every tool call, blocks leaked passwords and keys, and stops an agent when you say so.
</p>

<p align="center">
  <a href="#install">Install</a> ·
  <a href="#what-you-get">What you get</a> ·
  <a href="#faq">FAQ</a> ·
  <a href="#why-it-exists">Why it exists</a> ·
  <a href="#documentation">Docs</a> ·
  <a href="https://www.roro.im">Website</a>
</p>

<p align="center">
  <a href="https://github.com/timeomy/roro/actions/workflows/ci.yml"><img src="https://github.com/timeomy/roro/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://github.com/timeomy/roro/releases/latest"><img src="https://img.shields.io/github/v/release/timeomy/roro" alt="Latest release"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-blue" alt="License: Apache-2.0"></a>
  <a href="https://pkg.go.dev/github.com/timeomy/roro"><img src="https://pkg.go.dev/badge/github.com/timeomy/roro.svg" alt="Go reference"></a>
</p>

# Roro

**Roro is a free, open source security proxy for AI agents.** It sits between
your AI tool (Claude Code, Claude Desktop, Cursor, Windsurf, Codex) and the
MCP servers it uses. You do not change your AI tool or your servers, and you
do not need to know what MCP is.

> **Status: v0.3, pre-1.0.** The controls below are implemented and tested.
> Read [what Roro is not](#what-roro-is-not) and the
> [threat model](docs/threat-model.md) before relying on it.

## Install

macOS and Linux:

```sh
curl -fsSL https://www.roro.im/install.sh | sh
```

Windows (PowerShell):

```powershell
irm https://www.roro.im/install.ps1 | iex
```

The installer downloads Roro, checks the download, and runs `roro protect`.
That command lists the MCP servers it found, asks before it changes
anything, keeps a copy of every file it edits, and tells you which apps to
restart.

<img src="assets/demo.gif" width="860" alt="Roro demo in a terminal: roro protect puts Roro in front of a Cursor server, roro logs shows two allowed tool calls and one blocked because it carried a key, roro kill stops every agent, and the next call is denied">

The recording is a real run against a small stand-in server;
[scripts/demo-gif](scripts/demo-gif/make.py) reproduces it.

<details>
<summary><b>Read the installer before you run it</b></summary>
<br>

```sh
curl -fsSL https://www.roro.im/install.sh -o install.sh
less install.sh
sh install.sh
```

The same script is in this repository at
[scripts/install.sh](scripts/install.sh), and the Windows one at
[scripts/install.ps1](scripts/install.ps1). Set `RORO_NO_PROTECT=1` to
install Roro without touching any settings, then run
`roro protect --dry-run` to see what it would change.

</details>

<details>
<summary><b>Download a binary or build from source</b></summary>
<br>

Each [release](https://github.com/timeomy/roro/releases/latest) has static
builds for Linux, macOS, and Windows (amd64 and arm64) and a
`checksums.txt`. Unpack it and put `roro` somewhere on your `PATH`.

The binaries are not code-signed. On macOS, a binary downloaded with a
browser is quarantined; `curl` downloads are not. To clear it:
`xattr -d com.apple.quarantine roro`.

Or build with Go 1.27+:

```sh
go install github.com/timeomy/roro/cmd/roro@latest
```

</details>

## What you get

- **A signed log.** Every tool call your AI tools make is written down.
  `roro logs` shows it, and `roro verify` proves nobody changed it.
- **Leaked secrets are blocked.** A tool call that carries a password or key
  never reaches the server.
- **A stop button.** `roro kill` stops every agent at the next tool call.
- **Your own rules, when you want them.** Allow, deny, or ask a person, per
  agent and per tool. See [docs/policy.md](docs/policy.md).
- **An undo.** `roro unprotect` puts every file back the way it was.
- **A setup check.** `roro scan` reports risky MCP server entries before
  anything runs. See [Scan your setup](#scan-your-setup).

Run `roro protect` again after you add a new MCP server. Quit your AI apps
before you run it if you can, since some of them rewrite their settings while
open.

What it does not cover yet:

- servers that run on the internet (a URL, not a program on your computer),
- servers listed in a project's own `.mcp.json` file,
- entries written in an unusual way; these are listed as skipped, never
  guessed at.

Two choices in this setup favour "keeps working" over "strictest":
everything is allowed except leaking secrets, and when a server changes a
tool's description the change is logged, not blocked. The stricter
behaviour is one line each in `~/.roro/roro.yaml` and the policy file.

## FAQ

<details>
<summary><b>Do I need to know what MCP is?</b></summary>
<br>

No. MCP is how AI tools plug in extra abilities, such as reading files or
calling GitHub. If your AI tool has any of those set up, `roro protect`
finds them for you.

</details>

<details>
<summary><b>Is it free?</b></summary>
<br>

Yes. Roro is Apache-2.0 licensed. There is no account, no paid tier, and no
usage limit.

</details>

<details>
<summary><b>Does my data leave my computer?</b></summary>
<br>

Not through Roro. The log, the rules, and the signing key stay on your
computer, and Roro has no usage tracking. It only sends anything out if you
turn on telemetry and give it an address, and tool arguments are never
included. See [PRIVACY.md](PRIVACY.md).

</details>

<details>
<summary><b>Will it break my tools?</b></summary>
<br>

The setup `roro protect` installs allows everything except a call that
carries a password or key. If something stops working,
`roro logs --decision deny` shows what was blocked and why, and
`roro unprotect` turns Roro off again. See
[troubleshooting](docs/troubleshooting.md).

</details>

<details>
<summary><b>Does it stop prompt injection?</b></summary>
<br>

It does not detect it. Roro limits what an agent can do after it has been
tricked: the call still has to pass your rules, and it is still logged. See
[what Roro is not](#what-roro-is-not).

</details>

<details>
<summary><b>How do I remove it?</b></summary>
<br>

```sh
roro unprotect          # put your AI tools' settings back
rm ~/.local/bin/roro    # remove the program
rm -r ~/.roro           # remove the config, the log, and the signing key
```

On Windows the program is in `%LOCALAPPDATA%\Programs\roro`. Keep
`~/.roro` if you want to keep the log.

</details>

## Why it exists

AI agents now act through tools: they read files, call APIs, run commands.
The Model Context Protocol (MCP) made tools easy to plug in, but it leaves
open which agent may call which tool with which arguments, and it keeps no
trustworthy record of what happened.

Public guidance points the same way. NIST's design tenets for agent identity
call for distinct agent identities, least privilege, revocable authorization,
policy kept separate from the model's reasoning, and tamper-evident evidence.
The OWASP Top 10 for Agentic Applications warns about tool misuse, privilege
abuse, poisoned tools, and humans being talked into approving bad actions.
Joint guidance from CISA and partner agencies on deploying AI systems securely
asks for least privilege, strong logging, and monitoring around AI systems.

Roro puts those controls in one small binary between any MCP client and
any MCP server, without changing either:

- **Per-agent identity**: every decision is attributed to a named agent.
- **Policy as code**: [Cedar](https://www.cedarpolicy.com/) policies allow,
  deny, or require human approval for tool calls, with argument rules (path
  prefixes, host allowlists, numeric bounds, regex matchers) and rate limits.
- **Human approval**: risky calls wait for a person, who sees the actual tool
  name and arguments (secrets redacted), never a summary. No answer means no.
- **Tamper-evident audit log**: SQLite, SHA-256 hash chain, Ed25519-signed
  checkpoints, secret redaction, `roro verify`.
- **Kill switch**: stop all agents, or one, at the next tool call.
- **Tool pinning**: a tool whose description or schema changes is hidden and
  blocked until a human accepts it.
- **OpenTelemetry**: decisions as spans and metrics (GenAI/MCP conventions).

## Set it up by hand

```sh
mkdir -p ~/roro && cd ~/roro
roro init --agent my-agent   # config, starter policy, signing key
roro check                   # validate everything
```

Then see it stop an attack (builds everything into a temp dir, no network):

```sh
git clone https://github.com/timeomy/roro && cd roro
./scripts/demo.sh   # requires Go
```

A scripted agent reads a file containing a planted prompt injection and then
tries to read `/etc/passwd`, call an `exfiltrate` tool, and POST a key to an
attacker, first in the clear and then base64-encoded. Every attempt is
blocked and logged, the upstream server never sees them, `roro verify`
passes, and verifying a tampered copy of the log fails.

## Use with Claude Desktop or Cursor

`roro wrap` is a drop-in replacement for a stdio server command. Move the
original command after `--` and give the agent a name. Use absolute paths:
GUI apps start with a minimal `PATH`.

Before:

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem", "/Users/me/sandbox"]
    }
  }
}
```

After:

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "/usr/local/bin/roro",
      "args": [
        "--config", "/Users/me/roro/roro.yaml",
        "wrap", "--agent", "claude-desktop", "--client", "claude-desktop",
        "--", "npx", "-y", "@modelcontextprotocol/server-filesystem", "/Users/me/sandbox"
      ]
    }
  }
}
```

- Claude Desktop: `claude_desktop_config.json`, see
  [examples/claude-desktop](examples/claude-desktop/).
- Cursor: `~/.cursor/mcp.json` or `.cursor/mcp.json`, see
  [examples/cursor](examples/cursor/).

For HTTP clients, run `roro serve` and give each agent a token
(`roro token new --agent NAME`); see `roro serve --help`.

## What a denial looks like

The agent receives a normal tool result with `isError: true`, so it can tell
the user what happened, plus machine-readable metadata:

```json
{
  "content": [{"type": "text", "text": "Roro blocked the call to tool \"exfiltrate\" for agent \"research-bot\" (reason: dangerous_tool_blocked). denied by policy deny-dangerous-tools."}],
  "isError": true,
  "_meta": {"im.roro/decision": {"decision": "deny", "reason": "dangerous_tool_blocked", "policy_ids": ["deny-dangerous-tools"]}}
}
```

The call never reaches the upstream server. In the log:

```
$ roro logs --decision deny
SEQ  TIME (UTC)           KIND       AGENT         TOOL        DECISION  REASON                  ARGS
5    2026-11-16 15:56:49  tool_call  research-bot  exfiltrate  deny      dangerous_tool_blocked  {"data":"[REDACTED:aws_key]"}
```

Policies live in Cedar; see [docs/policy.md](docs/policy.md) and the starter
policy in [policies/examples/roro.cedar](policies/examples/roro.cedar).

## Approvals

When policy marks a call `@approval`, it waits (default 2 minutes) for a
human in any terminal:

```sh
roro approvals watch      # prompts y/N for each request, showing tool + args
roro approvals list
roro approvals approve 3f9a1c2b7d4e
```

## Verify the log

```sh
$ roro verify --require-sealed
events:       8 (last seq 8)
checkpoints:  1 (last covers seq 8)
unsealed:     0
anchor:       8:3f1c...e9a2
result:       OK - hash chain and signatures verified
```

`verify` needs only the public key (`.roro/audit-signing.key.pub`), so an
auditor can check a copy: `roro verify --log copy.db --pubkey key.pub`.
It also prints an `anchor:` line. Store it somewhere off the machine and
pass it back with `--expect SEQ:HASH`. That is what catches a log rolled
back to an earlier checkpoint, which the log alone cannot prove (see the
[threat model](docs/threat-model.md)).
It exits non-zero if any row was changed, removed, or reordered, a signature
is bad, or the log was cut short. `roro export -o audit.jsonl` exports
events and checkpoints with their hashes and signatures.

## Kill and resume

```sh
roro kill                                  # every agent, next call
roro kill --agent research-bot --reason "investigating"
roro status
roro resume --agent research-bot
roro resume
```

Every running Roro process that shares the state directory obeys at the
next tool call. The switch survives restarts. Kills and resumes are logged.

## Scan your setup

`roro scan` reads the MCP settings of Claude Code, Claude Desktop, Cursor,
Windsurf, Codex, and `./.mcp.json`, and lists risky server entries. It only
reads files: it never starts a server or connects to one.

```text
$ roro scan

Claude Desktop  ~/Library/Application Support/Claude/claude_desktop_config.json
  github
    HIGH   Secret written in the config file  RORO-S001
           env GITHUB_PERSONAL_ACCESS_TOKEN looks like a github token
           fix: Rotate it, then load it from an environment variable or your OS keychain. Anything that can read this file can read the secret.
    MEDIUM Package not pinned to a version  RORO-P001
           npx runs "@modelcontextprotocol/server-github", so a new release runs the next time your AI tool starts
           fix: Pin an exact version (name@1.2.3, name==1.2.3, or image:tag / image@sha256:...) and update on purpose.
    LOW    Tool calls are not checked  RORO-G001
           nothing checks or logs what your agent asks this server to do
           fix: Run `roro protect` to put Roro in front of it.

Scanned 1 server in 1 file. Found 1 high, 1 medium, 1 low.
roro: 1 finding at or above the --fail-on level
```

| Rule | Severity | What it finds |
|---|---|---|
| RORO-S001 | high | a key, token, or password written in the file (env, headers, arguments, URL) |
| RORO-S002 | medium | a credential-named setting holding a plain value instead of `${VAR}` |
| RORO-N001 | high | a remote server over plain `http://` (localhost is fine) |
| RORO-C001 | high | a container run with `--privileged`, the Docker socket, or the host disk mounted |
| RORO-P001 | medium | `npx`, `uvx`, `pipx`, `pnpm dlx`, `docker run` and similar without an exact version |
| RORO-F001 | medium | a server given the whole disk or your whole home folder |
| RORO-C002 | low | a container on the host network |
| RORO-X001 | low | a server started through `sh -c` or `cmd /c` |
| RORO-G001 | low | a local server Roro does not protect |
| RORO-G002 | info | a remote server, which Roro cannot check yet |
| RORO-G003 | info | an entry written in a form Roro does not fully read |

Secrets are never printed: a finding names where the secret is and what it
looks like, not its value. `roro scan` exits 1 when a finding reaches
`--fail-on` (default `high`, or `none`), so it can gate CI:

```sh
roro scan --file .mcp.json --fail-on medium
roro scan --json > mcp-scan.json
roro scan --show info          # also list low and info findings
```

Secret detection is pattern matching: it finds known token formats and
credential-named settings, not every secret. A scan is a check of what is
written down; what a server does at run time is what `roro protect` is for.

## Tool pinning

The first `tools/list` pins each tool's definition. If a server later changes
a description or schema, Roro hides that tool and denies its calls until
you review it:

```sh
roro pins list
roro pins accept --server filesystem --tool read_file
```

## Telemetry

Set `telemetry.otlp_endpoint` (OTLP/HTTP, e.g. `localhost:4318`). Each
`tools/call` becomes a span named `tools/call <tool>` with `mcp.method.name`,
`gen_ai.tool.name`, `gen_ai.operation.name=execute_tool`, `gen_ai.agent.name`,
and `roro.decision` / `roro.reason`. Metrics:
`mcp.server.operation.duration` and `roro.decisions`. Arguments and
results are never exported. The GenAI conventions are still marked
"Development" upstream; the names used are pinned in
[testdata/semconv-genai-mcp.json](testdata/semconv-genai-mcp.json).

## Documentation

- [docs/architecture.md](docs/architecture.md): design, packages, protocols
- [docs/policy.md](docs/policy.md): writing Cedar policy for Roro
- [docs/threat-model.md](docs/threat-model.md): what is defended, known limits
- [docs/nist-owasp-mapping.md](docs/nist-owasp-mapping.md): OWASP Agentic Top 10
  and NIST agent-identity tenets, enforced vs. documented only
- [docs/troubleshooting.md](docs/troubleshooting.md): common problems and fixes
- [CHANGELOG.md](CHANGELOG.md): what changed in each release
- [PRIVACY.md](PRIVACY.md): what stays on your computer
- [SECURITY.md](SECURITY.md): reporting vulnerabilities

## Tests

```sh
go test -race ./...
```

Unit tests cover each package (policy decisions per rule type, hash chain
tampering and truncation, kill switch persistence, pinning, redaction,
approval timeouts). End-to-end tests run the real binary over stdio and HTTP,
including the prompt-injection exfiltration scenario.

## What Roro is not

- Not a prompt-injection detector or content filter. It limits what an
  injected agent can do; it does not see the model's input.
- Not a sandbox. An allowed tool runs with the upstream server's privileges.
- Not a hosted service, dashboard, SSO product, or multi-tenant control plane.
- Not complete protection on its own: pair it with least-privilege servers,
  sandboxing, and review of the tools you permit.

## Contributing and citing

Contributions are welcome: read [CONTRIBUTING.md](CONTRIBUTING.md) first.
Questions and ideas go in
[Discussions](https://github.com/timeomy/roro/discussions). To cite Roro, use
[CITATION.cff](CITATION.cff) or the "Cite this repository" button on GitHub.

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE); third-party licenses
are in [third_party/LICENSES.txt](third_party/LICENSES.txt).

## Maintainer

Built and maintained by Jabez Kok.
