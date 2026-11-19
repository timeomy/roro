# Mapping to OWASP and NIST

This maps Roro v0.2 controls to two public frameworks. Each row says
whether the control is **enforced** by code (and tested), **partial**, or
**documented only / out of scope**. Where Roro does nothing, it says so.

Sources (read 2026-11-16):

- OWASP GenAI Security Project, "OWASP Top 10 for Agentic Applications: The
  Benchmark for Agentic Security in the Age of Autonomous AI", 9 December 2025.
  <https://genai.owasp.org/2025/12/09/owasp-top-10-for-agentic-applications-the-benchmark-for-agentic-security-in-the-age-of-autonomous-ai/>
- NIST Cybersecurity Insights blog, "Design Tenets for Agent Identity
  Management Systems", H. Booth, B. Fisher, R. Galluzzo (NIST) and T. Clancy
  (MITRE), 27 October 2026.
  <https://www.nist.gov/blogs/cybersecurity-insights/design-tenets-agent-identity-management-systems>

## OWASP Top 10 for Agentic Applications (2026)

| ID | Risk | Roro v0.2 | Status | Evidence |
|---|---|---|---|---|
| ASI01 | Agent Goal Hijack | No detection of hijacked goals. If a hijacked agent calls a tool, the call is still checked against policy, so the damage is bounded by what the agent is allowed to do. | Partial | `tests/attack_exfil_test.go` |
| ASI02 | Tool Misuse | Default-deny Cedar policy with allow / deny / require-approval; argument rules (cleaned paths, URL hosts, numeric bounds, regex matchers); per-agent and per-tool rate limits. Attack demo: an injected instruction to call an exfiltration tool is denied and logged. | Enforced | `internal/policy/cedar_test.go`, `internal/gate/gate_test.go`, `tests/attack_exfil_test.go`, `scripts/demo.sh` |
| ASI03 | Identity & Privilege Abuse | Every decision is attributed to a named agent principal; policies are per agent; no standing broad access (default deny); HTTP agents authenticate with per-agent tokens and sessions are bound to them. | Enforced (stdio identity is configuration-asserted, see threat model) | `internal/identity`, `internal/proxy/http_test.go`, `tests/http_test.go` |
| ASI04 | Agentic Supply Chain Vulnerabilities | Tool-definition pinning: name, description, schemas, and annotations are hashed on first sight; a later change hides the tool and blocks calls until a human accepts it. Does not vet a server the first time (trust on first use) or verify server binaries. | Partial | `internal/pin/pin_test.go`, `internal/gate/pin_test.go`, `tests/controls_test.go` |
| ASI05 | Unexpected Code Execution | Execution-style tools (`*exec*`, `*shell*`, `*run_command*`) are forbidden by the starter policy unless an explicit exception is written; everything else is default-deny. Name matching is heuristic. Roro does not sandbox the server. | Partial | `internal/policy/cedar_test.go` |
| ASI06 | Memory & Context Poisoning | Not addressed. Roro does not see or filter model context or memory. | Out of scope | None |
| ASI07 | Insecure Inter-Agent Communication | Not addressed. Roro is an MCP tool gateway, not an agent-to-agent protocol layer. | Out of scope | None |
| ASI08 | Cascading Failures | Rate limits in policy; fail-closed config and policy loading; a call that cannot be audited is denied; kill switch stops all agents at the next call. | Enforced | `internal/config/config_test.go`, `internal/gate/gate_test.go` (`TestAuditFailureFailsClosed`), `tests/controls_test.go` |
| ASI09 | Human-Agent Trust Exploitation | Approval requests show the actual tool name and arguments (secrets redacted, with a warning when values are hidden), never a model-written rationale; the gate forwards exactly the parsed call the human saw; no answer before the timeout denies; decisions are audited with the approver. A human can still approve a harmful call. | Enforced (UX) | `internal/approval/cli_test.go`, `tests/controls_test.go` (`TestHumanApprovalViaCLI`) |
| ASI10 | Rogue Agents | Global and per-agent kill switch, effective on the next call in every Roro process, persistent across restarts; resume is explicit and logged. | Enforced | `internal/killswitch/killswitch_test.go`, `tests/controls_test.go` (`TestKillSwitchAcrossProcesses`) |

## NIST design tenets for agent identity management

| # | Tenet (NIST heading) | Roro v0.2 | Status |
|---|---|---|---|
| 01 | Distinct Agent Identification | Each agent has its own principal (`Roro::Agent::"name"`) used in every decision and audit event. HTTP agents have distinct tokens. Identities are names and bearer tokens, not cryptographically verifiable workload identities. | Partial |
| 02 | Agent Linking, Delegation & Attenuation | Agents carry an `owner` attribute available to policy and logged at session start. No delegation chains or attenuation to sub-agents. | Documented only |
| 03 | Least & Zero Standing Privilege | Default deny: an agent can call nothing until a policy permits it, scoped by tool, arguments, and server. Permissions do not expire on their own (no just-in-time grants). | Partial |
| 04 | Short-Lived, Dynamic & Revocable Authorization | Every call is authorized at call time against current policy and state; the kill switch revokes an agent at the next call; HTTP sessions expire when idle. HTTP tokens are long-lived static secrets, which the tenet advises against. | Partial |
| 05 | Human-in-the-Loop Triggers | `@approval` policies define which calls need a human; the request shows full call context; timeouts deny. No built-in measures against approval fatigue beyond keeping approvals rare by policy. | Enforced |
| 06 | Mandates and Constraints | Not implemented: no signed mandates from a task originator. | Out of scope |
| 07 | Architectural Separation of Policy from Reasoning | Authorization runs in a separate process, outside the model, in Cedar policy the model cannot change; a prompt injection cannot add permissions. | Enforced |
| 08 | Deterministic Access Decisions | Decisions are deterministic Cedar evaluations over call data and runtime facts. No ML classifier is in the decision path. | Enforced |
| 09 | Continuous Monitoring | Every decision is logged and exported as OpenTelemetry spans and a decision counter; rate counters feed policy. No anomaly detection. | Partial |
| 10 | Immutable Evidence | Append-only, hash-chained audit log with Ed25519-signed checkpoints, kept by Roro rather than the agent; `roro verify` detects modified, missing, reordered, or truncated records. The unsealed tail and whole-log deletion are not detectable locally (see threat model). | Enforced, with documented limits |

## What "enforced" means here

A control is listed as enforced only if Roro's code applies it on every
`tools/call`, fails closed when it cannot, and a test in this repository shows
the unsafe case being denied. Everything else is labelled partial,
documented only, or out of scope.
