<p>
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/logo-dark.svg">
    <img src="assets/logo.svg" alt="Roro" width="220">
  </picture>
</p>

# Roro

Roro sits between your AI agent and its tools. It checks every tool call
against your rules, can ask a person before a risky one runs, keeps a signed
log of each decision, and can stop an agent at any time.

It is a standalone proxy for the Model Context Protocol (MCP). You do not
change your client or your servers.

> **Status: v0.2, pre-1.0.** The controls below are implemented and tested.
> Read [what Roro is not](#what-roro-is-not) and the
> [threat model](docs/threat-model.md) before relying on it.

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

## Install

**Download a binary.** Each [release](https://github.com/timeomy/roro/releases/latest)
has static builds for Linux, macOS, and Windows (amd64 and arm64) and a
`checksums.txt`. For example, on an Apple Silicon Mac:

```sh
curl -fsSLO https://github.com/timeomy/roro/releases/download/v0.2.2/roro_0.2.2_darwin_arm64.tar.gz
curl -fsSLO https://github.com/timeomy/roro/releases/download/v0.2.2/checksums.txt
shasum -a 256 --ignore-missing -c checksums.txt
tar -xzf roro_0.2.2_darwin_arm64.tar.gz
sudo mv roro_0.2.2_darwin_arm64/roro /usr/local/bin/
roro version
```

The binaries are not code-signed. On macOS, a binary downloaded with a
browser is quarantined; `curl` downloads are not. To clear it:
`xattr -d com.apple.quarantine roro`.

**Or build with Go 1.27+:**

```sh
go install github.com/timeomy/roro/cmd/roro@latest
```

## 60-second quickstart

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

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE); third-party licenses
are in [third_party/LICENSES.txt](third_party/LICENSES.txt).

## Maintainer

Built and maintained by Jabez Kok.
