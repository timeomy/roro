# Cursor

Config file: `~/.cursor/mcp.json` (all projects) or `.cursor/mcp.json` (one
project).

1. `roro init --dir ~/roro --sandbox ~/roro/sandbox --agent cursor`
2. Wrap each server, as in [`mcp.json`](mcp.json), with absolute paths.
3. Open Cursor Settings > MCP and check the server is connected.

Blocked calls show as tool errors that start with "Roro blocked the
call". Run `roro logs` to see why, and `roro approvals watch` in a
terminal if your policy uses approvals.
