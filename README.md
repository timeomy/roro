# Tollgate

Tollgate is a standalone MCP proxy that enforces per-agent permissions,
optional human approval, a tamper-evident audit log, and a kill switch for
tool calls.

> **Status: pre-release, milestone M1 of 5.** Today Tollgate is a transparent
> stdio pass-through proxy. It does **not** enforce any policy yet. Policy,
> audit, approval, pinning, kill switch, and HTTP transport land in M2–M4.
> See [Roadmap](#roadmap). Do not rely on it as a security control until
> v0.1.0.

## Why it exists

AI agents now call real tools: they read files, hit APIs, run commands. The
Model Context Protocol (MCP) made those tools easy to plug in, but it does not
say *which agent may call which tool with which arguments*, and it leaves no
trustworthy record of what happened. Public guidance from NIST, CISA, and the
OWASP Top 10 for Agentic Applications points the same way: give each agent its
own identity, grant least privilege, keep authorization outside the model,
keep humans in the loop for risky actions, keep tamper-evident evidence, and
be able to revoke an agent quickly.

Tollgate is a small, single-binary policy enforcement point that does those
things between any MCP client and any MCP server, without changing either.

## Quickstart (M1)

Requires Go 1.27 or newer.

```sh
git clone https://github.com/timeomy/tollgate && cd tollgate
go build -o bin/tollgate ./cmd/tollgate
go build -o bin/echo-server ./examples/echo-server
./bin/tollgate version
```

Run any stdio MCP server through Tollgate by putting `wrap --` in front of its
command:

```sh
./bin/tollgate wrap -- ./bin/echo-server
```

Tollgate's own logs go to **stderr**; stdout carries only MCP traffic. The
upstream server's stderr is passed through. Add `--log-level debug` to log
each relayed message (method and id only, never arguments).

## Use with Claude Desktop or Cursor

`wrap` is a drop-in replacement for the server command. Take your existing
server entry, move its `command` into `args` after `"wrap", "--"`, and set
`command` to the absolute path of `tollgate`.

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
      "command": "/usr/local/bin/tollgate",
      "args": ["wrap", "--", "npx", "-y", "@modelcontextprotocol/server-filesystem", "/Users/me/sandbox"]
    }
  }
}
```

- Claude Desktop: `claude_desktop_config.json`, see
  [examples/claude-desktop](examples/claude-desktop/).
- Cursor: `~/.cursor/mcp.json` or `.cursor/mcp.json`, see
  [examples/cursor](examples/cursor/).

Use absolute paths: GUI apps often start with a minimal `PATH`.

## Tests

```sh
go test -race ./...
```

- `internal/proxy`: in-memory relay tests (tools/list, tools/call, ping,
  clean disconnect, cancellation, and delivery of in-flight responses after
  the client closes its input).
- `tests/`: builds the real `tollgate` and `examples/echo-server` binaries
  and checks that results through `tollgate wrap` are identical, field for
  field, to calling the server directly, including tool errors and
  unknown-tool errors.

## Roadmap

| Milestone | Scope | State |
|-----------|-------|-------|
| M1 | Transparent stdio pass-through proxy | done |
| M2 | Agent identity, Cedar policy (allow/deny, argument rules), clean MCP errors, fail closed | next |
| M3 | Hash-chained, signed SQLite audit log, redaction, `verify`/`logs`/`export`, kill switch | planned |
| M4 | Human approval (CLI), tool-definition pinning, streamable HTTP, rate limits | planned |
| M5 | OpenTelemetry, threat model, NIST/OWASP mapping, demo script, CI, v0.1.0 | planned |

## What Tollgate is not

- Not a model runtime, prompt filter, or prompt-injection classifier.
- Not a container sandbox or orchestrator for MCP servers.
- Not a hosted service, dashboard, or SSO product.

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).

## Maintainer

Built and maintained by Jabez Kok.
