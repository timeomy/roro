# Threat model

This document says what Tollgate defends against, how, and where it stops.
The control-by-control mapping to OWASP and NIST is in
[nist-owasp-mapping.md](nist-owasp-mapping.md).

## System and assets

Tollgate runs between an MCP client (the agent's host) and an MCP server (the
tools). Assets:

- the systems and data the tools can reach (files, APIs, credentials),
- the integrity of the record of what agents did (the audit log),
- the ability to stop an agent quickly (kill switch).

## Trust assumptions

- The **host running Tollgate** and its state directory are trusted. An
  attacker with write access to `.tollgate/` can turn the kill switch off,
  edit pins, or approve requests. They cannot rewrite audit history without
  the signing key and without `verify` noticing (see limits below).
- The **audit signing key** is secret. Whoever holds it can sign checkpoints.
- The **policy and config files** are authored by the operator.
- The **agent and model are not trusted.** Any tool call may be the result of
  prompt injection, a malicious tool description, or a confused model.
- The **upstream MCP server** is partly trusted: Tollgate cannot stop it from
  doing harm inside an allowed call, but it pins the server's tool
  definitions and never forwards a denied call.
- For **stdio**, the agent identity comes from the MCP client config that
  launched `tollgate wrap`. Anyone who can edit that config can choose the
  name. For **HTTP**, identity comes from a bearer token.

## Threats and controls

| # | Threat | Control | Enforced? |
|---|---|---|---|
| T1 | Injected instructions make the agent call a dangerous tool (exfiltrate, exec, send_email) | Default-deny Cedar policy; forbid rules for execution/exfiltration-style tool names | Yes |
| T2 | Allowed tool used with harmful arguments (path traversal, foreign host, oversized request) | Argument rules over cleaned `resource.paths`, parsed `resource.hosts`, numeric bounds; regex matchers for secrets | Yes, for top-level arguments |
| T3 | Secret sent out inside tool arguments | `context.matches` + forbid; host allowlist + approval for anything else | Partly: regex finds known formats only; encoded secrets are caught only by the host rule |
| T4 | Silent change of a tool's description or schema ("rug pull", tool poisoning) | Tool-definition pinning; changed tools hidden and blocked until accepted | Yes, after first observation (trust on first use) |
| T5 | A human is tricked into approving | Approval prompt shows the raw tool name and arguments (redacted), never a model summary; timeout denies | Yes; the human can still approve a bad call |
| T6 | Runaway agent loops or floods tools | Per-agent and per-tool rate counters in policy | Yes, per process |
| T7 | Agent goes rogue during operation | Global and per-agent kill switch, next call, all processes, persists | Yes |
| T8 | Someone edits the audit log to hide activity | Hash chain + Ed25519 checkpoints + `verify` | Yes, with the limits below |
| T9 | Secrets end up in logs or telemetry | Redaction before logging; telemetry carries no arguments | Best effort (pattern-based) |
| T10 | Policy/config error silently allows everything | Strict config; policy parse errors stop startup; erroring forbid policies deny | Yes |
| T11 | Another HTTP client hijacks a session | Bearer token per request; session bound to the creating agent; origin check | Yes |
| T12 | Audit log unavailable, calls go unrecorded | A call that cannot be logged is not forwarded | Yes |

## Known limits (read these)

**Audit log**

- Events after the most recent checkpoint are protected by the hash chain but
  not yet by a signature. Deleting them is not detectable. Tollgate
  checkpoints every `audit.checkpoint_every` events, on clean shutdown, and on
  kill/resume; `verify --require-sealed` fails if any event is unsealed. A
  crash leaves an unsealed tail.
- Deleting the entire log (or the newest checkpoints together with the rows
  they cover) cannot be detected locally. Anchoring checkpoints outside the
  machine (Sigstore Rekor, or simply copying checkpoints elsewhere) is the fix
  and is future work.
- Anyone with the signing key can produce a new, valid history.

**Policy inputs**

- `resource.paths` is cleaned lexically. Symlinks inside an allowed directory
  that point outside it are not detected (Tollgate cannot see the upstream's
  filesystem). Keep sandboxes free of symlinks, or run the server in a
  container.
- Only top-level string arguments get `paths` / `hosts` entries. Tools that
  nest paths or URLs need rules over `resource.args` written with that in
  mind, or a server-side check.
- Tool-name patterns (`*exec*`) are heuristics. A server can expose a
  dangerous tool under an innocent name; the default-deny posture is what
  protects you, so only permit tools you have reviewed.
- Regex matchers find known secret formats. Base64, splitting, or any custom
  encoding defeats them. The host allowlist is the stronger control.

**Scope**

- Tollgate sees tool calls, not model inputs. It does not detect prompt
  injection; it limits what an injected agent can do.
- An allowed tool can still do harm within its permission (an allowed write
  can write bad content). Tollgate narrows permissions; it does not verify
  intent.
- Tool results are passed to the agent unchanged (only their digest is
  logged). A malicious result can still inject the model; the next tool call
  is what Tollgate checks.
- Rate counters are per Tollgate process; several processes for the same
  agent each count separately.
- Pinning is trust on first use: a tool that is malicious the first time it
  is listed is pinned as-is. Review new tools (`tollgate pins list`).
- Calls made before the client lists tools are checked against
  `pin_status: unknown` and are not blocked by pinning.
- HTTP mode does not carry server-initiated requests or notifications
  (no GET stream) in v0.1.
- Approval: the human sees redacted arguments. A secret-bearing argument
  shows as `[REDACTED:...]`.

## Out of scope for v0.1

Prompt-injection classifiers (for example NeMo Guardrails, LlamaFirewall,
Prompt Shields), memory and context poisoning, agent-to-agent protocols, and
sandboxing the upstream server. These complement Tollgate.
