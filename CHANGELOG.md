# Changelog

Every release, newest first. Each heading is the version, the date, and one
line on what the release is about. The release page on GitHub is built from
the matching section.

## 0.4.0 (2026-11-24): Scan your MCP setup for risky entries

### New

- **`roro scan`.** Checks the MCP settings of Claude Code, Claude Desktop,
  Cursor, Windsurf, Codex, and `./.mcp.json` for risky entries: secrets
  written in the file, packages not pinned to a version, plain HTTP remote
  servers, access to the whole disk or home folder, privileged containers,
  shell launchers, and servers Roro does not protect. It only reads files and
  never prints a secret. `--json` for machines, `--fail-on` to gate CI.
- **Codex settings are read with a full TOML parser** when scanning, so
  multi-line strings and inline tables are checked and a broken file is
  reported instead of half read. `roro protect` still edits the file line by
  line and keeps your comments.
- **JSON files with comments or trailing commas** now get a clear error
  message in `roro protect` and `roro scan`.

## 0.3.0 (2026-11-19): One step setup for every MCP client

### New

- **`roro protect`.** Finds the MCP servers set up in Claude Code, Claude
  Desktop, Cursor, Windsurf, and Codex, lists them, asks first, and puts Roro
  in front of each one. It keeps a copy of every file it edits and never
  guesses at an entry it does not understand.
- **`roro unprotect`.** Puts every file back the way it was.
- **One line installers.** `install.sh` for macOS and Linux and `install.ps1`
  for Windows download the release, check its SHA-256 checksum, add Roro to
  your `PATH`, and run `roro protect`.
- **Everyday policy.** The setup `roro protect` installs allows tool calls,
  blocks any call that carries a password or key, limits each agent to 120
  calls a minute, and keeps the kill switch.
- **`roro wrap --server NAME`** names the server in the log.
- **Home config.** When there is no `./roro.yaml`, Roro reads
  `~/.roro/roro.yaml`, so `roro logs` and `roro kill` work from any folder.

### Good to know

- Remote servers (a URL, not a program on your computer) and servers in a
  project's own `.mcp.json` are not covered yet. They are listed as skipped.
- With the everyday policy, a changed tool description is logged, not
  blocked. The stricter behaviour is one line in `~/.roro/roro.yaml`.

## 0.2.2 (2026-11-19): Correct version for go install builds

### Fixed

- `roro version` reported `dev` when Roro was installed with `go install`.
  It now reports the module version.
- Audit and gate tests closed their databases too late for Windows to clean
  up the temp folder.

## 0.2.1 (2026-11-19): Release binaries

### New

- Each release now ships static binaries for Linux, macOS, and Windows on
  amd64 and arm64, with a `checksums.txt`.
- The README documents installing from a release.

## 0.2.0 (2026-11-17): Renamed from Tollgate to Roro

### Changed

- The project, binary, module path, config file, and metadata keys are now
  named Roro. Anything that referred to `tollgate` needs the new name.

### Fixed

- Hardened the gate against the findings of a security review.

## 0.1.0 (2026-11-17): First release

### New

- Transparent MCP proxy over stdio (`roro wrap`) and HTTP (`roro serve`).
- A named identity for every agent.
- Cedar policy that allows, denies, or asks a person, with argument rules
  and rate limits.
- Human approval for risky calls. No answer means no.
- Audit log with a SHA-256 hash chain and Ed25519 signed checkpoints,
  secret redaction, and `roro verify`.
- Kill switch for one agent or all of them.
- Tool pinning: a tool whose description or schema changes is held until a
  person accepts it.
- OpenTelemetry spans and metrics for every decision.
- Threat model, NIST and OWASP mapping, policy guide, and an attack demo.
