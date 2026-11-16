# Cursor

Config file: `~/.cursor/mcp.json` (all projects) or `.cursor/mcp.json` (one
project).

1. `tollgate init --dir ~/tollgate --sandbox ~/tollgate/sandbox --agent cursor`
2. Wrap each server, as in [`mcp.json`](mcp.json), with absolute paths.
3. Open Cursor Settings > MCP and check the server is connected.

Blocked calls show as tool errors that start with "Tollgate blocked the
call". Run `tollgate logs` to see why, and `tollgate approvals watch` in a
terminal if your policy uses approvals.
