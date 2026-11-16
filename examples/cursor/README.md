# Cursor

Config file: `~/.cursor/mcp.json` (all projects) or `.cursor/mcp.json` (one
project). `mcp.json` in this folder wraps the Tollgate echo server; replace
the paths with your own.

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

After saving, open Cursor Settings > MCP and check the server shows as
connected with the `echo` and `fail` tools.
