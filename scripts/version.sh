#!/bin/sh
# The root `Version` file is the single source of truth for Rat's version. project.yml carries a copy in
# MARKETING_VERSION (XcodeGen cannot read a file); this script keeps the two in step and CI runs `check`.
#
#   scripts/version.sh get           print the version
#   scripts/version.sh set 1.4.0     write Version and project.yml
#   scripts/version.sh check         fail when project.yml disagrees with Version, or Version is malformed
#   scripts/version.sh next-minor    print X.(Y+1).0
set -eu
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
FILE="$ROOT/Version"
SPEC="$ROOT/project.yml"
PATTERN='^[0-9]+\.[0-9]+\.[0-9]+$'

get() { tr -d '[:space:]' < "$FILE"; }
valid() { printf '%s\n' "$1" | grep -Eq "$PATTERN"; }
spec_version() { sed -n 's/^ *MARKETING_VERSION: *"\{0,1\}\([^"]*\)"\{0,1\} *$/\1/p' "$SPEC" | head -n 1; }

case "${1:-}" in
  get) get ;;
  set)
    v="${2:-}"
    valid "$v" || { echo "usage: $0 set X.Y.Z" >&2; exit 2; }
    printf '%s\n' "$v" > "$FILE"
    sed -i '' "s/^\( *MARKETING_VERSION: *\).*/\1$v/" "$SPEC" 2>/dev/null || sed -i "s/^\( *MARKETING_VERSION: *\).*/\1$v/" "$SPEC"
    echo "$v" ;;
  check)
    v="$(get)"
    valid "$v" || { echo "Version: '$v' is not X.Y.Z" >&2; exit 1; }
    s="$(spec_version)"
    [ "$s" = "$v" ] || { echo "project.yml MARKETING_VERSION is '$s' but Version is '$v' (run: scripts/version.sh set $v)" >&2; exit 1; }
    echo "version $v" ;;
  next-minor)
    v="$(get)"
    IFS=. read -r major minor _ <<EOF
$v
EOF
    echo "$major.$((minor + 1)).0" ;;
  *) sed -n '2,8p' "$0" | sed 's/^# \{0,1\}//'; exit 2 ;;
esac
