# Claude Desktop

Config file:

- macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
- Windows: `%APPDATA%\Claude\claude_desktop_config.json`

1. `tollgate init --dir ~/tollgate --sandbox ~/tollgate/sandbox --agent claude-desktop`
2. Wrap each server you want Tollgate to guard, as in
   [`claude_desktop_config.json`](claude_desktop_config.json). Replace the
   paths with absolute paths on your machine.
3. Restart Claude Desktop.

Tollgate's log lines appear in Claude Desktop's MCP log for that server
(`~/Library/Logs/Claude/mcp-server-<name>.log` on macOS). If the server fails
to start, run the same command in a terminal: Tollgate refuses to start, with
a message, when the config, policy, or signing key is missing.

Use a different `--agent` name per client (for example `cursor` and
`claude-desktop`) so policy and logs can tell them apart.
