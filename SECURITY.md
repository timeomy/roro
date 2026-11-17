# Security policy

Roro is a security control, so we treat vulnerabilities in it seriously.

## Reporting a vulnerability

Please report privately. Do not open a public issue for a suspected
vulnerability.

Use GitHub's private vulnerability reporting for this repository:
**Security tab > Report a vulnerability**
(`https://github.com/timeomy/roro/security/advisories/new`).

Include, if you can:

- the Roro version (`roro version`) and OS,
- your `roro.yaml` and policy (redact secrets),
- the MCP messages or steps that reproduce the issue,
- what you expected and what happened.

You can expect an acknowledgement within 5 working days and a first
assessment within 14 days. We will agree a disclosure date with you; by
default we publish an advisory once a fix is released, and credit you unless
you ask us not to.

## Scope

In scope: anything that lets a tool call reach an upstream server without the
decision the policy specifies, defeats the kill switch or tool pinning, lets
a modified, truncated, or reordered audit log pass `roro verify` (beyond
the limits documented in [docs/threat-model.md](docs/threat-model.md)), leaks
secrets into the audit log, approval queue, logs, or telemetry, or bypasses
HTTP authentication or session binding.

Out of scope: weaknesses of the upstream MCP servers themselves, prompt
injection that does not lead to a policy bypass (Roro does not claim to
detect it), and the limits listed as known in the threat model.

## Supported versions

Roro is pre-1.0. Only the latest release receives security fixes.
