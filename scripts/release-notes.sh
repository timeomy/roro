#!/bin/sh
# Print the release title or notes for one version, read from CHANGELOG.md.
#
#   scripts/release-notes.sh title v0.3.0   ->  v0.3.0: One step setup ...
#   scripts/release-notes.sh notes v0.3.0   ->  the body of that section
#
#   scripts/release-notes.sh check v0.3.0   ->  fails unless CITATION.cff
#                                               names the same version
#
# Every mode fails if the changelog has no section for the version, so a
# release cannot go out undocumented.
set -eu

mode="${1:?usage: release-notes.sh title|notes|check VERSION}"
version="${2:?usage: release-notes.sh title|notes|check VERSION}"
version="${version#v}"
root="$(cd "$(dirname "$0")/.." && pwd)"
log="$root/CHANGELOG.md"

heading="$(awk -v v="$version" 'index($0, "## " v " (") == 1 { print; exit }' "$log")"
if [ -z "$heading" ]; then
  echo "CHANGELOG.md has no section for $version" >&2
  exit 1
fi

case "$mode" in
  title)
    summary="${heading#*): }"
    if [ "$summary" = "$heading" ]; then
      echo "v$version"
    else
      echo "v$version: $summary"
    fi
    ;;
  notes)
    awk -v v="$version" '
      index($0, "## " v " (") == 1 { on = 1; next }
      on && /^## / { exit }
      on { print }
    ' "$log" | sed -e '/./,$!d'
    ;;
  check)
    cited="$(awk '$1 == "version:" { print $2; exit }' "$root/CITATION.cff")"
    if [ "$cited" != "$version" ]; then
      echo "CITATION.cff says version $cited, expected $version" >&2
      exit 1
    fi
    ;;
  *)
    echo "unknown mode: $mode" >&2
    exit 1
    ;;
esac
