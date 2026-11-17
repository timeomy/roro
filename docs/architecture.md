# Architecture

Roro is a policy enforcement point for MCP tool calls. It is a single Go
binary that sits between an MCP client and an upstream MCP server. It is not a
model runtime, a prompt filter, or a container orchestrator.

```
MCP client (Claude Desktop, Cursor, custom agent)
        |  MCP over stdio (wrap) or streamable HTTP (serve)
        v
+--------------------------------------------------------------------+
| Roro                                                           |
|  proxy    relay JSON-RPC messages; only tools/call and the         |
|           tools/list response are inspected, all else passes       |
|  gate     per-connection Session:                                  |
|    1. identity        agent principal (flag/env/config or token)   |
|    2. kill switch     global + per-agent, shared SQLite state      |
|    3. pinning         tool definition hash vs. first-seen pin      |
|    4. facts           rate counters, regex matchers, derived       |
|                       paths/hosts                                  |
|    5. policy          Cedar: allow | deny | require_approval       |
|    6. approval        CLIApprover queue; timeout = deny            |
|    7. audit           hash-chained, signed SQLite log (redacted)   |
|    8. forward         or answer with an isError tool result        |
|    9. result          tool_result event: latency, result digest    |
|   10. telemetry       OTel span + metrics (no arguments)           |
+--------------------------------------------------------------------+
        |  MCP over stdio (child process) or streamable HTTP
        v
Upstream MCP server
```

## Packages

| Package | Responsibility |
|---|---|
| `cmd/roro` | CLI (cobra). Help text is part of the product. |
| `internal/proxy` | Message relay (stdio), streamable HTTP server, child process lifecycle. Knows nothing about policy; calls an `Interceptor`. |
| `internal/gate` | The enforcement pipeline. Implements `proxy.Interceptor`. |
| `internal/policy` | `Engine` interface; `CedarEngine`; entity mapping; matchers; rate counter. |
| `internal/approval` | `Approver` interface; `CLIApprover` (SQLite queue). |
| `internal/audit` | `Log` interface; `HashChainSQLiteLog`; keys; verify; query; export. |
| `internal/killswitch` | Global and per-agent switch in shared state. |
| `internal/pin` | Tool-definition pinning store. |
| `internal/redact` | Secret redaction for logs, approvals, telemetry. |
| `internal/observe` | OpenTelemetry spans and metrics. |
| `internal/identity` | Agent principals and the bearer-token directory. |
| `internal/config` | Strict `roro.yaml` loading. |
| `internal/app` | Assembles components from config; fail-closed startup. |
| `internal/store` | SQLite open helper (pure-Go driver, immediate transactions). |

Interfaces exist where the spec expects a second implementation:
`policy.Engine` (an OPA backend could follow), `approval.Approver` (Slack or
Telegram), `audit.Log`.

## Proxy model

Roro relays MCP at the JSON-RPC message level. It does not run its own MCP
server that re-exports upstream tools. Methods it does not inspect
(resources, prompts, sampling, elicitation, logging, future additions) keep
working unchanged in stdio mode.

Framing and message types come from the official MCP Go SDK
(`mcp.IOTransport`, `jsonrpc.Message`). The relay loop, HTTP endpoint,
process handling, and every enforcement component are Roro's own.

`tools/call` requests may wait for a human, so the relay handles each on its
own goroutine; all other messages are handled in order, so `initialize`
always precedes `notifications/initialized` upstream.

### stdio (`roro wrap`)

`wrap -- CMD ARGS...` starts `CMD` with piped stdin/stdout and passes its
stderr through. Shutdown follows the MCP stdio guidance: when the client
closes Roro's stdin, Roro closes the child's stdin (half-close),
keeps forwarding its output for a grace period so in-flight responses arrive,
then signals and finally kills it. The SDK's `CommandTransport` closes both
directions at once, so Roro manages the process itself.

### Streamable HTTP (`roro serve`)

A small, original implementation of the server side of the MCP streamable
HTTP transport at `/mcp`:

- `POST` carries one JSON-RPC message. Requests get an `application/json`
  response; notifications and responses get `202 Accepted`.
- `initialize` without `Mcp-Session-Id` creates a session (random id from
  `crypto/rand`); later requests must send it. `DELETE` ends it; idle
  sessions are reaped.
- Every request needs `Authorization: Bearer <token>`. Tokens map to agents
  through SHA-256 digests in config. A session is bound to the agent that
  created it; another agent's token gets `404`.
- Browser `Origin` headers other than loopback (or `http.allowed_origins`)
  are rejected (DNS-rebinding defence).
- `GET` returns `405`: v0.1 does not offer the optional server-to-client
  event stream. Upstream-initiated requests other than `ping` are answered
  with "method not found"; upstream notifications are dropped. Use stdio mode
  for servers that need sampling or elicitation.
- Each session gets its own upstream process (or HTTP connection), so one
  agent's session state never leaks into another's.

The SDK's `StreamableHTTPHandler` is built around the SDK's own `Server`
type, which Roro does not use, so Roro implements the handler.

## Audit log

- Table `events`: one row per decision, tool result, session start/end,
  kill/resume, pin change/accept. SQL triggers reject `UPDATE` and `DELETE`.
- `entry_hash = SHA-256(canonical(event))`, where the canonical form is a
  domain string followed by every hashed field in fixed order, each
  length-prefixed (`<len>:<bytes>\n`). It includes `prev_hash`; the first
  event's `prev_hash` is 64 zeros (`audit.GenesisHash`).
- Appends run in a `BEGIN IMMEDIATE` transaction that reads the chain head
  and inserts, so concurrent Roro processes cannot fork the chain.
- Table `checkpoints`: every `audit.checkpoint_every` events, on clean
  shutdown, and on kill/resume, Roro signs
  `roro/audit/checkpoint/v1 \n seq \n entry_hash \n ts \n key_id` with
  Ed25519. The key lives outside the log (`.roro/audit-signing.key`,
  mode 0600); `init` creates it and Roro never creates one implicitly.
- `roro verify` needs only the public key and never writes. The spec
  asked for a checkpoint "on verify"; Roro deliberately does not, so an
  auditor can verify a read-only copy with only the public key.
- Arguments are stored only as a redacted preview (512 bytes) and the
  SHA-256 of the full redacted JSON. Results are stored only as a SHA-256
  digest.
- Key rotation is not implemented in v0.1. `init` refuses to overwrite a key.

## Identity

stdio: one agent per `wrap` process, from `--agent`, `$RORO_AGENT`, or
`agent.name`. Run separate `wrap` entries (with different `--agent`) for
different clients. The stdio identity is asserted by whoever configures the
MCP client; it is as trustworthy as that config file.

HTTP: the bearer token determines the agent.

## Inspiration and differences

Roro's code is original. Ideas it shares with other projects:

- **Tool pinning** follows the "tool poisoning / rug pull" defence popularised
  by Invariant Labs' mcp-scan (now Snyk agent-scan): hash tool descriptions
  and alert on change. Roro enforces it inline, per call, instead of as a
  scan.
- **A gateway in front of MCP servers** is the shape of Docker MCP Gateway,
  IBM ContextForge, Lasso MCP Gateway, and agentgateway. Roro differs by
  scope: one small binary focused on per-agent authorization in Cedar,
  human approval, signed audit evidence, and revocation; no container
  orchestration, registry, UI, or multi-tenant control plane.
- **Signed checkpoints over a hash chain** follow the transparency-log idea
  behind Sigstore Rekor and Certificate Transparency, in a local, offline
  form. Anchoring checkpoints in Rekor is future work.
