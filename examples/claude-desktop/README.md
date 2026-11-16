# Claude Desktop

Config file:

- macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
- Windows: `%APPDATA%\Claude\claude_desktop_config.json`

Wrap each server you want Tollgate to guard. `claude_desktop_config.json` in
this folder wraps the Tollgate echo server; replace the paths with your own.

```json
{
  "mcpServers": {
    "echo-via-tollgate": {
      "command": "/absolute/path/to/tollgate",
      "args": ["wrap", "--", "/absolute/path/to/echo-server"]
    }
  }
}
```

Restart Claude Desktop after editing. Tollgate's log lines appear in Claude
Desktop's MCP server log for that entry (`mcp-server-echo-via-tollgate.log`
on macOS, under `~/Library/Logs/Claude/`).
