#!/bin/sh
# Installs Roro for macOS and Linux, then offers to protect the MCP servers
# your AI tools already use.
#
#   curl -fsSL https://www.roro.im/install.sh | sh
#
# It downloads the latest release from GitHub, checks its SHA-256 against the
# release's checksums.txt, and puts the `roro` program in ~/.local/bin.
# Nothing needs administrator rights.
#
# Settings (environment variables):
#   RORO_INSTALL_DIR   where to put roro (default: ~/.local/bin)
#   RORO_VERSION       a release tag such as v0.3.0 (default: the latest)
#   RORO_NO_PROTECT=1  install only; do not run `roro protect`
set -eu

repo="timeomy/roro"
dest="${RORO_INSTALL_DIR:-$HOME/.local/bin}"

say() { printf '%s\n' "$*"; }
fail() { say "roro install: $*" >&2; exit 1; }

command -v curl >/dev/null 2>&1 || fail "curl is required"
command -v tar >/dev/null 2>&1 || fail "tar is required"

case "$(uname -s)" in
  Darwin) os=darwin ;;
  Linux) os=linux ;;
  *) fail "this installer supports macOS and Linux. On Windows, see https://www.roro.im" ;;
esac
case "$(uname -m)" in
  x86_64 | amd64) arch=amd64 ;;
  arm64 | aarch64) arch=arm64 ;;
  *) fail "unsupported processor: $(uname -m)" ;;
esac

tag="${RORO_VERSION:-}"
if [ -z "$tag" ]; then
  latest=$(curl -fsSLI -o /dev/null -w '%{url_effective}' "https://github.com/$repo/releases/latest") ||
    fail "could not reach GitHub"
  tag="${latest##*/}"
fi
case "$tag" in
  v[0-9]*) ;;
  *) fail "could not work out the latest version (got '$tag')" ;;
esac

name="roro_${tag#v}_${os}_${arch}"
base="https://github.com/$repo/releases/download/$tag"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT INT TERM

say "Downloading Roro $tag for $os/$arch..."
curl -fsSL -o "$tmp/$name.tar.gz" "$base/$name.tar.gz" || fail "download failed: $base/$name.tar.gz"
curl -fsSL -o "$tmp/checksums.txt" "$base/checksums.txt" || fail "download failed: $base/checksums.txt"

want=$(awk -v f="$name.tar.gz" '$2 == f { print $1 }' "$tmp/checksums.txt")
[ -n "$want" ] || fail "no checksum listed for $name.tar.gz"
if command -v sha256sum >/dev/null 2>&1; then
  got=$(sha256sum "$tmp/$name.tar.gz" | awk '{ print $1 }')
elif command -v shasum >/dev/null 2>&1; then
  got=$(shasum -a 256 "$tmp/$name.tar.gz" | awk '{ print $1 }')
else
  fail "need sha256sum or shasum to check the download"
fi
[ "$want" = "$got" ] || fail "checksum mismatch: the download is damaged or was tampered with"

tar -xzf "$tmp/$name.tar.gz" -C "$tmp"
mkdir -p "$dest"
cp "$tmp/$name/roro" "$dest/roro.new"
chmod 755 "$dest/roro.new"
mv -f "$dest/roro.new" "$dest/roro"
say "Installed $("$dest/roro" version) to $dest/roro"

# Make `roro` available in new terminal windows.
case ":$PATH:" in
  *":$dest:"*) ;;
  *)
    case "${SHELL:-}" in
      */zsh) rc="$HOME/.zshrc" ;;
      */bash) rc="$HOME/.bashrc" ;;
      *) rc="$HOME/.profile" ;;
    esac
    line="export PATH=\"$dest:\$PATH\""
    if ! grep -qsF "$line" "$rc"; then
      printf '\n# Added by the Roro installer\n%s\n' "$line" >>"$rc"
      say "Added $dest to your PATH in $rc. Open a new terminal window to use the roro command."
    fi
    ;;
esac

if [ "${RORO_NO_PROTECT:-0}" = "1" ]; then
  exit 0
fi
say ""
if [ -r /dev/tty ] && [ -w /dev/tty ]; then
  "$dest/roro" protect </dev/tty
else
  say "Next step: run  $dest/roro protect"
fi
