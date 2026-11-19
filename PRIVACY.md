# Privacy

Roro runs on your computer. It has no account, no usage tracking, and no
server of ours to talk to.

## What stays on your computer

- Your rules, in `roro.yaml` and the policy file.
- The signed log of tool calls, in the state folder (`~/.roro/state` after
  `roro protect`). Passwords and keys found in tool arguments are replaced
  with a `[REDACTED:...]` marker before anything is written.
- The signing key for that log.
- The copy of each settings file that `roro protect` edits
  (`NAME.before-roro`, next to the original).

## What Roro connects to

| When | Where | What is sent |
|---|---|---|
| Always | The MCP servers you already use | The tool calls your AI tool makes, when your rules allow them. Roro passes them on unchanged. |
| Only if you set `telemetry.otlp_endpoint` | The address you set | Timing and decision for each tool call (tool name, agent name, allow or deny, reason). Tool arguments and results are never sent. |

Nothing else. Roro does not check for updates and does not phone home.

## What the installer connects to

`install.sh` and `install.ps1` are downloaded from `www.roro.im`. They then
download the Roro release and its `checksums.txt` from `github.com` and
compare the SHA-256 checksum before installing. Those two sites see your IP
address, as any website does.

## Your AI tool

Roro sits between your AI tool (Claude Code, Cursor, and so on) and its MCP
servers. What your AI tool sends to its own provider is up to that tool and
is not changed by Roro.
