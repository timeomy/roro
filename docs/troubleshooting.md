# Troubleshooting

## `roro: command not found`

The installer adds Roro to your `PATH`, but a terminal that was already open
does not see the change. Open a new terminal window. If it still fails, the
binary is at `~/.local/bin/roro` on macOS and Linux and at
`%LOCALAPPDATA%\Programs\roro\roro.exe` on Windows.

## macOS says the file cannot be opened

This happens when you download the binary with a browser. Clear the
quarantine flag:

```sh
xattr -d com.apple.quarantine roro
```

Downloads made by the installer or by `curl` are not affected.

## A tool stopped working after `roro protect`

Look at what Roro blocked and why:

```sh
roro logs --decision deny
```

The `REASON` column names the rule. With the everyday policy the usual cause
is a tool call that carried something shaped like a password or key.

To rule Roro out, run `roro unprotect`, restart the app, and try again. Run
`roro protect` to turn it back on.

## A new MCP server is not protected

`roro protect` only changes the servers it finds when you run it. Run it
again after you add a server.

## My settings changed back

Some apps rewrite their settings file while they are open. Quit the app, run
`roro protect`, then start the app again.

## A server is listed as skipped

Roro does not cover these yet, and leaves them exactly as they were:

- servers that run on the internet (a URL, not a program on your computer),
- servers in a project's own `.mcp.json` file,
- entries written in a way Roro does not recognise.

## Every call is denied

Check whether the kill switch is on:

```sh
roro status
roro resume
```

## A tool disappeared

Only if you turned on strict tool pinning. A tool whose description or
schema changed is hidden until you accept it:

```sh
roro pins list
roro pins accept --server NAME --tool TOOL
```

## Something is wrong with the config

```sh
roro check
```

It validates the config, the policy, and the signing key, and says what
is wrong.

## Still stuck

Ask in [Discussions](https://github.com/timeomy/roro/discussions), or open a
[bug report](https://github.com/timeomy/roro/issues/new/choose) with the
output of `roro version`.
