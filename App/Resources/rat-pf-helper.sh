#!/bin/sh
# Rat pf helper. Installed root-owned as a LaunchDaemon; re-runs whenever Rat rewrites the
# blocklist. It only ever reads IP addresses (anything else is ignored) and loads them into
# a pf table inside the "com.apple/rat" anchor, then kills existing connections to them.
#
# Usage: rat-pf-helper <blocklist-file>      Set RAT_DRYRUN=1 to print the pfctl calls instead.
LIST="$1"
ANCHOR="com.apple/rat"
PFCTL="${RAT_PFCTL:-/sbin/pfctl}"

run() { if [ -n "$RAT_DRYRUN" ]; then echo "$@"; else "$@" >/dev/null 2>&1; fi; }

IPS=""
if [ -r "$LIST" ]; then
  IPS=$(awk '
    /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ { split($0, o, "."); ok = 1
      for (i = 1; i <= 4; i++) if (o[i] + 0 > 255) ok = 0
      if (ok) print; next }
    /^[0-9a-fA-F:]+$/ && /:.*:/ && length($0) <= 39 { print }
  ' "$LIST" | sort -u | head -5000)
fi

RULES='table <rat_blocked> persist
block drop out quick from any to <rat_blocked>
block drop in quick from <rat_blocked> to any'

if [ -n "$RAT_DRYRUN" ]; then echo "rules:"; echo "$RULES"; else
  echo "$RULES" | "$PFCTL" -a "$ANCHOR" -f - >/dev/null 2>&1
fi

if [ -z "$IPS" ]; then
  run "$PFCTL" -a "$ANCHOR" -t rat_blocked -T flush
  exit 0
fi

# shellcheck disable=SC2086
run "$PFCTL" -a "$ANCHOR" -t rat_blocked -T replace $IPS
run "$PFCTL" -E

for ip in $IPS; do
  case "$ip" in
    *:*) run "$PFCTL" -k "::/0" -k "$ip" ;;
    *)   run "$PFCTL" -k "0.0.0.0/0" -k "$ip" ;;
  esac
done
