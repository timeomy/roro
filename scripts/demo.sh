#!/usr/bin/env bash
# One-command Tollgate demo: a prompt injection tries to exfiltrate a secret
# through an MCP server; Tollgate denies it, logs it, and the log verifies.
# Then a copy of the log is tampered with and verification fails.
#
# Requires Go. Everything happens in a temporary directory; nothing touches
# the network (the demo server only records attempted "sends" to a file).
set -euo pipefail
cd "$(dirname "$0")/.."

work=$(mktemp -d "${TMPDIR:-/tmp}/tollgate-demo.XXXXXX")
work=$(cd "$work" && pwd -P)
bin="$work/bin"
cfg="$work/tollgate.yaml"
hr() { printf '\n\033[1m== %s ==\033[0m\n' "$*"; }

hr "Build"
CGO_ENABLED=0 go build -o "$bin/" ./cmd/tollgate ./examples/demo-exfil-server ./examples/demo-agent
echo "binaries in $bin"

hr "tollgate init"
"$bin/tollgate" init --dir "$work" --agent research-bot
# Short approval timeout so the demo does not wait two minutes.
sed -i.bak 's/timeout: 2m/timeout: 3s/' "$cfg" && rm -f "$cfg.bak"

hr "Hijacked agent runs through Tollgate (approval timeout 3s)"
DEMO_EXFIL_LOG="$work/exfil.log" "$bin/demo-agent" --sandbox "$work/sandbox" -- \
  "$bin/tollgate" --config "$cfg" --log-level warn wrap --agent research-bot -- "$bin/demo-exfil-server"

hr "Did anything reach the exfil handlers?"
if [[ -s "$work/exfil.log" ]]; then
  echo "YES - this should not happen:"; cat "$work/exfil.log"; exit 1
fi
echo "No. The upstream server never received an exfiltration call."

hr "tollgate logs"
"$bin/tollgate" --config "$cfg" logs

hr "tollgate verify"
"$bin/tollgate" --config "$cfg" verify --require-sealed

hr "Tamper with a copy of the log (turn a deny into an allow) and verify again"
cp "$work/.tollgate/audit.db" "$work/tampered.db"
go run ./scripts/tamper "$work/tampered.db"
if "$bin/tollgate" verify --log "$work/tampered.db" --pubkey "$work/.tollgate/audit-signing.key.pub"; then
  echo "verify passed on a tampered log - this should not happen"; exit 1
fi
echo "(non-zero exit, as expected)"

hr "Done"
echo "workspace: $work"
