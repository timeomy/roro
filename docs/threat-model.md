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
- **Approvals and the kill switch rest on OS file permissions.** `tollgate
  approvals approve`, `tollgate resume`, and direct writes to `state.db` are
  not authenticated beyond that; `decided_by` is `cli:<os user>`. With
  `wrap`, the agent's MCP server usually runs as the same OS user as
  Tollgate, so an agent that already has a shell tool could approve its own
  request or clear the kill switch. Do not permit shell-capable tools to an
  agent you rely on approvals for, or run Tollgate's state under a different
  OS user from the upstream server.
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
| T5 | A human is tricked into approving | Approval prompt shows the actual tool name and arguments (secrets redacted, with a warning when values are hidden), never a model summary; timeout denies | Yes; the human can still approve a bad call |
| T6 | Runaway agent loops or floods tools | Per-agent and per-tool rate counters in policy | Yes, per process |
| T7 | Agent goes rogue during operation | Global and per-agent kill switch, next call, all processes, persists | Yes |
| T8 | Someone edits the audit log to hide activity | Hash chain + Ed25519 checkpoints + `verify` | Yes, with the limits below |
| T9 | Secrets end up in logs or telemetry | Redaction before logging; telemetry carries no arguments | Best effort (pattern-based) |
| T10 | Policy/config error silently allows everything | Strict config; policy parse errors stop startup; erroring forbid policies deny | Yes |
| T11 | Another HTTP client hijacks a session | Bearer token per request; session bound to the creating agent; origin check | Yes |
| T12 | Audit log unavailable, calls go unrecorded | A call that cannot be logged is not forwarded | Yes |
| T13 | Proxy and upstream read the same request differently (duplicate or case-variant JSON keys), so policy approves one call and the server runs another | Params with duplicate keys, case-variant keys, or nesting deeper than 64 are refused; the gate forwards params it re-encoded itself, never the received bytes | Yes |
| T14 | Argument values policy cannot represent (numbers beyond 64-bit, `1e400`) slip past numeric bounds | Unrepresentable numbers deny with `policy_evaluation_error` | Yes |
| T15 | State changes while a call waits for approval | Kill switch and pin status are checked again after a human approves | Yes |
| T16 | Terminal escape sequences in tool names or arguments rewrite the approval prompt | Tool names limited to `A-Z a-z 0-9 . _ : / -`, 1-128 chars; CLI output escapes control and bidi characters | Yes |
| T17 | An authenticated agent exhausts resources | Caps on HTTP sessions (total and per agent), approval waits per process, unanswered requests per session; HTTP read/write/idle timeouts; rate-counter keys expire; metric series capped | Yes, within the caps |

## Known limits (read these)

**Audit log**

- Events after the most recent checkpoint are protected by the hash chain but
  not yet by a signature. Deleting them is not detectable. Tollgate
  checkpoints every `audit.checkpoint_every` events, on clean shutdown, and on
  kill/resume; `verify --require-sealed` fails if any event is unsealed. A
  crash leaves an unsealed tail.
- Someone with write access to the log file can drop the SQL triggers (they
  only stop accidents) and roll the log back to **any earlier checkpoint**,
  deleting every later event and checkpoint. The result verifies cleanly,
  even with `--require-sealed`: the log cannot prove on its own what it used
  to contain. Deleting the entire log is the extreme case. The defence is an
  anchor kept elsewhere: `verify` prints `anchor: <seq>:<hash>` for the
  latest checkpoint; record it outside the machine (a ticket, a remote log)
  and pass it back with `verify --expect <seq>:<hash>`, which fails on a
  rollback or rewrite past it. Automatic external anchoring (for example
  Sigstore Rekor) is future work.
- `verify` defaults to the `.pub` file next to the signing key. Someone who
  can write the state directory can replace both and re-sign a new history.
  Auditors should keep their own copy of the public key and pass `--pubkey`.
- Anyone with the signing key can produce a new, valid history.

**Policy inputs**

- `resource.paths` is cleaned lexically. Symlinks inside an allowed directory
  that point outside it are not detected (Tollgate cannot see the upstream's
  filesystem). Keep sandboxes free of symlinks, or run the server in a
  container.
- Only top-level string arguments get `paths` / `hosts` entries, under their
  own names. A rule over `resource.paths.path` says nothing about another
  argument (`url2`, or a nested `opts.path`): `read_file {"path":
  "/sandbox/x", "opts": {"path": "/etc/passwd"}}` passes a rule that checks
  only `path`. Prefer tools with a fixed argument shape, constrain the full
  argument set in policy, or check on the server.
- Hosts come from Go's `net/url` parser. Some inputs that browsers and other
  WHATWG-style parsers accept (for example `https:/evil.example`) are not
  recognised as URLs and get no `hosts` entry. An allowlist (`hosts.url in
  [...]`) fails safe; a denylist of hosts would be bypassed. Write allowlists.
- Cedar `like` is case-sensitive. `"*exec*"` does not match `EXEC_cmd`.
  Default-deny is what makes the starter policy safe; do not rely on name
  patterns in a default-allow policy.
- A JSON `null` argument is treated as absent (`has` is false), because
  Cedar has no null and MCP servers treat a null optional argument as
  unset. A bound written as `!(resource.args has limit) || ...` therefore
  lets `"limit": null` through, meaning the server's default applies.
  Require the argument if that default is unacceptable.
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
  shows as `[REDACTED...]`, and anything under a secret-looking key (for
  example `x_token`) is hidden entirely; the prompt then prints a warning
  that the server receives the original values. Since the agent chooses
  argument names, treat a prompt with hidden values as suspicious and deny
  when you cannot tell what the call does.
- Messages over stdio are read without a size cap (HTTP bodies are capped
  by `http.max_body_bytes`). A hostile client on stdio is the user's own
  MCP client process, so this is a robustness limit, not an access bypass.
- Denials tell the agent the reason and the IDs of the policies involved.
  That helps the model explain a block to the user, and also tells a
  probing agent which rule stopped it.

## Out of scope for v0.1

Prompt-injection classifiers (for example NeMo Guardrails, LlamaFirewall,
Prompt Shields), memory and context poisoning, agent-to-agent protocols, and
sandboxing the upstream server. These complement Tollgate.
