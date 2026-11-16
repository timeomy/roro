# Architecture

This document grows with each milestone. It currently describes M1.

## Proxy model

Tollgate relays MCP at the **JSON-RPC message level**. It does not run an MCP
server of its own that re-exports the upstream's tools. Every request,
response, and notification is read from one side and written to the other.

Why:

- Fidelity. Methods Tollgate does not inspect (resources, prompts, sampling,
  elicitation, logging, and future protocol additions) keep working unchanged.
- One choke point. M2+ intercepts only the methods that need enforcement
  (`tools/call`, and `tools/list` for pinning) and passes everything else.

Framing and message types come from the official MCP Go SDK
(`mcp.IOTransport`, `jsonrpc.Message`). The relay loop, process handling, and
all enforcement code are Tollgate's own.

```
client stdin/stdout ──IOTransport──▶ Relay ──IOTransport──▶ upstream child stdin/stdout
                                       │
                         (M2+) identity → kill switch → pinning → policy
                               → approval → forward → redact → audit → OTel
```

## Process lifecycle (stdio)

`tollgate wrap -- CMD ARGS...` starts `CMD` with piped stdin/stdout and
passes its stderr through to Tollgate's stderr.

Shutdown follows the MCP stdio transport guidance:

1. Client closes Tollgate's stdin (EOF).
2. Tollgate closes the upstream's stdin (half-close) and keeps forwarding the
   upstream's output for a grace period, so responses already in flight still
   reach the client.
3. When the upstream exits, or the grace period ends, Tollgate closes both
   sides, then sends SIGTERM, waits again, and finally kills the process.

If the upstream exits first, Tollgate exits non-zero so the MCP host notices.
SIGINT/SIGTERM to Tollgate cancel the relay and run the same shutdown.

Tollgate manages the child process itself rather than using the SDK's
`CommandTransport`, because that transport closes the whole connection at
once and cannot half-close.

## Logging

`log/slog` text handler on stderr. Stdout is reserved for protocol traffic.
At debug level the relay logs method, id, and direction per message; it never
logs arguments or results (redaction lands with the audit log in M3).
