// Tollgate starter policy.
//
// Entity model:
//   principal  Tollgate::Agent::"<name>"      attrs: name, client, owner
//   action     Tollgate::Action::"call_tool"
//   resource   Tollgate::Tool::"<tool name>"  attrs: name, server, args, paths, hosts
//   context    now, kill_switch, pin_status, rate.{agent,tool}_calls_per_minute,
//              matches.<matcher name>
//
// resource.paths.<arg> is the lexically cleaned form of a path-like string
// argument ("/sandbox/../etc" -> "/etc"). Always constrain paths through
// resource.paths, never resource.args.
// resource.hosts.<arg> is the lowercase hostname of a URL argument.
//
// Decisions:
//   - no permit matches               -> deny (no_matching_permit)
//   - any forbid matches              -> deny (its @reason)
//   - a plain permit matches          -> allow
//   - only an @approval permit matches -> require_approval (human decides)
//
// `tollgate init --sandbox DIR` replaces /sandbox below with your directory.

// ---------------------------------------------------------------- safety nets

// The kill switch is also enforced in Tollgate's code before policy runs;
// this rule documents it and keeps policy-only evaluation honest.
@id("kill-switch")
@reason("kill_switch_active")
forbid (principal, action, resource)
when { context.kill_switch };

@id("rate-limit-agent")
@reason("rate_limit_exceeded")
forbid (principal, action, resource)
when { context.rate.agent_calls_per_minute > 30 };

@id("rate-limit-write-tools")
@reason("rate_limit_exceeded")
forbid (principal, action, resource)
when {
  (resource.name like "*write*" || resource.name like "*delete*") &&
  context.rate.tool_calls_per_minute > 5
};

// Execution- and exfiltration-style tools are denied unless an exception is
// written here. Example exception: ops-bot may use run_shell.
@id("deny-dangerous-tools")
@reason("dangerous_tool_blocked")
forbid (principal, action, resource)
when {
  resource.name like "*exec*" ||
  resource.name like "*shell*" ||
  resource.name like "*run_command*" ||
  resource.name like "*exfil*" ||
  resource.name like "*send_email*"
}
unless { principal == Tollgate::Agent::"ops-bot" && resource.name == "run_shell" };

// Arguments that carry credentials never leave through a tool call.
// The matcher names are defined under `matchers:` in tollgate.yaml.
@id("deny-secrets-in-args")
@reason("secret_in_arguments")
forbid (principal, action, resource)
when {
  (context.matches has aws_access_key && context.matches.aws_access_key) ||
  (context.matches has private_key_block && context.matches.private_key_block)
};

// ---------------------------------------------------------------- filesystem

@id("fs-read-sandbox")
permit (principal, action, resource)
when {
  ["read_file", "fs.read", "list_directory"].contains(resource.name) &&
  resource.paths has path &&
  resource.paths.path like "/sandbox/*"
};

@id("fs-write-sandbox")
permit (principal, action, resource)
when {
  ["write_file", "fs.write"].contains(resource.name) &&
  resource.paths has path &&
  resource.paths.path like "/sandbox/*"
};

@id("fs-write-outside-sandbox")
@reason("write_outside_sandbox")
forbid (principal, action, resource)
when { ["write_file", "fs.write"].contains(resource.name) }
unless { resource.paths has path && resource.paths.path like "/sandbox/*" };

// ---------------------------------------------------------------- network

@id("http-allowlisted-hosts")
permit (principal, action, resource)
when {
  ["http.request", "http_post", "fetch"].contains(resource.name) &&
  resource.hosts has url &&
  ["api.github.com", "docs.python.org"].contains(resource.hosts.url)
};

@id("http-other-hosts-need-approval")
@approval
@reason("http_host_not_allowlisted")
permit (principal, action, resource)
when { ["http.request", "http_post", "fetch"].contains(resource.name) };

// ---------------------------------------------------------------- misc

// Numeric bound: search results capped at 100.
@id("search-bounded")
permit (principal, action, resource)
when {
  resource.name == "search" &&
  (!(resource.args has limit) || resource.args.limit <= 100)
};

@id("harmless-tools")
permit (principal, action, resource)
when { ["echo", "fail", "get_time"].contains(resource.name) };
