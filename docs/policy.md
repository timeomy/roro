# Writing Tollgate policy

Tollgate authorizes every `tools/call` with [Cedar](https://www.cedarpolicy.com/)
policies (via the official [cedar-go](https://github.com/cedar-policy/cedar-go)
library). Policy files are listed under `policy.files` in `tollgate.yaml`.
`tollgate init` writes a commented starter policy; `tollgate check` validates
config and policy without proxying.

## Entity model

| Cedar element | Tollgate meaning |
|---|---|
| `principal` | `Tollgate::Agent::"<name>"` with attributes `name`, `client`, `owner` |
| `action` | `Tollgate::Action::"call_tool"` |
| `resource` | `Tollgate::Tool::"<tool name>"` with attributes `name`, `server`, `args`, `paths`, `hosts` |
| `context` | `now` (Unix seconds), `kill_switch`, `pin_status`, `rate.agent_calls_per_minute`, `rate.tool_calls_per_minute`, `matches.<matcher>` |

- `resource.args` is the tool's arguments converted to Cedar values: strings,
  booleans, integers as `Long`, other numbers as `decimal`, arrays as sets,
  objects as records. `null` and unrepresentable values are omitted, so
  `has` checks treat them as absent.
- `resource.paths.<arg>` exists for each top-level string argument that looks
  like a filesystem path (starts with `/`, `./`, `../`, `~`, a drive letter,
  or `file://`). It is the lexically cleaned path: `/sandbox/../etc/passwd`
  becomes `/etc/passwd`. **Constrain paths through `resource.paths`, never
  `resource.args`.** Relative paths without `./` get no entry, so a
  prefix rule does not match them (fail closed).
- `resource.hosts.<arg>` exists for each top-level string argument that is an
  `http`, `https`, `ws`, or `wss` URL: the lowercase hostname, trailing dot
  removed. `https://api.github.com@evil.example/` yields `evil.example`.
- `context.pin_status` is `pinned`, `changed`, or `unknown` (never listed
  through Tollgate).
- `context.rate.*` count attempts (allowed or not) in the last 60 seconds,
  including the current call, for this agent and for this agent + tool.
  Counters are per Tollgate process.
- `context.matches.<name>` is `true` if the named matcher (configured in
  `tollgate.yaml`) matched any string anywhere in the arguments.

## Outcomes

Cedar itself only says permit or forbid. Tollgate derives three outcomes:

| Situation | Outcome | Reason code |
|---|---|---|
| any `forbid` matches | deny | the forbid's `@reason`, else `forbidden_by_policy` |
| a plain `permit` matches, no forbid | allow | `permitted` |
| only an `@approval` permit matches | require_approval | the permit's `@reason`, else `approval_required` |
| nothing matches | deny | `no_matching_permit` |
| a `forbid` fails to evaluate (e.g. missing attribute) | deny | `policy_evaluation_error` |

**Design choice: annotation.** `require_approval` is a `permit` annotated with
`@approval`. At load time Tollgate splits policies into an "unattended" set
(everything without `@approval`) and an "approval" set (`@approval` permits
plus all forbids). This keeps one action, one entity model, and Cedar's rule
that forbids always win. `@approval` on a `forbid` is a load error.

Annotations Tollgate reads:

- `@id("name")`: the policy id shown in audit events (default `file.cedar:N`).
  Must be unique.
- `@reason("snake_case_code")`: the stable reason code for a forbid or
  approval permit.
- `@approval`: this permit allows the call only after a human approves.

## Approval

A `require_approval` call is queued and waits up to `approval.timeout`. A
human answers with `tollgate approvals watch` (interactive), or `approvals
list` + `approvals approve|deny ID`. No answer means deny
(`approval_timeout`). If the client cancels the request
(`notifications/cancelled`) or disconnects, the wait stops
(`approval_cancelled`). In monitor mode, nothing waits for approval.

## Examples

Allow reads under a directory:

```cedar
@id("fs-read-sandbox")
permit (principal, action, resource)
when {
  ["read_file", "fs.read"].contains(resource.name) &&
  resource.paths has path &&
  resource.paths.path like "/home/me/sandbox/*"
};
```

Deny writes outside it (forbid beats any permit):

```cedar
@id("fs-write-outside-sandbox")
@reason("write_outside_sandbox")
forbid (principal, action, resource)
when { ["write_file", "fs.write"].contains(resource.name) }
unless { resource.paths has path && resource.paths.path like "/home/me/sandbox/*" };
```

HTTP: allowlisted hosts unattended, everything else needs a human:

```cedar
@id("http-allowlisted-hosts")
permit (principal, action, resource)
when {
  resource.name == "http.request" &&
  resource.hosts has url &&
  ["api.github.com"].contains(resource.hosts.url)
};

@id("http-other-hosts-need-approval")
@approval
@reason("http_host_not_allowlisted")
permit (principal, action, resource)
when { resource.name == "http.request" };
```

Numeric bound:

```cedar
permit (principal, action, resource)
when { resource.name == "search" && (!(resource.args has limit) || resource.args.limit <= 100) };
```

Per-agent rule:

```cedar
permit (principal == Tollgate::Agent::"ops-bot", action, resource)
when { resource.name == "restart_service" && resource.server == "ops" };
```

Rate limit (tighter for write tools):

```cedar
@id("rate-limit-write-tools")
@reason("rate_limit_exceeded")
forbid (principal, action, resource)
when { resource.name like "*write*" && context.rate.tool_calls_per_minute > 5 };
```

Secrets in arguments (matchers are defined in `tollgate.yaml`; use `has` so
the policy keeps working if a matcher is removed):

```cedar
@id("deny-secrets-in-args")
@reason("secret_in_arguments")
forbid (principal, action, resource)
when { context.matches has aws_access_key && context.matches.aws_access_key };
```

## Order of checks

1. Kill switch (code, not policy: no policy can override it).
2. Tool pinning: in enforce mode with `on_change: block`, a changed tool is
   denied before policy runs.
3. Rate counters and matchers are computed.
4. Cedar decides.
5. `require_approval` waits for a human.
6. The decision is appended to the audit log. If that fails, the call is
   denied (`audit_unavailable`).

## Monitor mode

`mode: monitor` evaluates everything and logs what would have happened
(`reason: monitor:<code>`), but forwards calls. The kill switch still blocks.
Use it to tune a policy on real traffic before enforcing it.
