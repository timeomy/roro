// Roro everyday policy, written by `roro protect`.
//
// It is made for people who want protection without writing rules:
//   - every tool call is logged,
//   - passwords and keys are stopped from leaving through a tool call,
//   - a runaway agent is slowed down,
//   - everything else works as before.
//
// To lock things down further, see docs/policy.md and the stricter starter
// policy in policies/examples/roro.cedar.

// `roro kill` stops every agent at its next tool call.
@id("kill-switch")
@reason("kill_switch_active")
forbid (principal, action, resource)
when { context.kill_switch };

// More than 120 tool calls a minute from one agent is not normal use.
@id("rate-limit-agent")
@reason("rate_limit_exceeded")
forbid (principal, action, resource)
when { context.rate.agent_calls_per_minute > 120 };

// A tool call that carries a secret is blocked. The patterns are listed
// under `matchers:` in roro.yaml.
@id("deny-secrets-in-args")
@reason("secret_in_arguments")
forbid (principal, action, resource)
when {
  (context.matches has aws_access_key && context.matches.aws_access_key) ||
  (context.matches has private_key_block && context.matches.private_key_block) ||
  (context.matches has github_token && context.matches.github_token) ||
  (context.matches has api_secret_key && context.matches.api_secret_key) ||
  (context.matches has google_api_key && context.matches.google_api_key) ||
  (context.matches has slack_token && context.matches.slack_token) ||
  (context.matches has stripe_live_key && context.matches.stripe_live_key)
};

@id("allow-everything-else")
permit (principal, action, resource);
