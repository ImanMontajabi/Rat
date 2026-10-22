#!/bin/sh
# Rat root helper. Installed root-owned as two LaunchDaemons (opt-in, with the user's admin password):
#   apply    - runs whenever Rat rewrites its blocklist: loads the addresses into a pf table inside the
#              "com.apple/rat" anchor and kills existing connections to them.
#   snapshot - runs every few seconds: lists every process's sockets (lsof as root) so Rat can show
#              processes of other users and system daemons that an unprivileged app cannot see.
#
# Usage: rat-pf-helper apply <blocklist-file>
#        rat-pf-helper snapshot <output-file> <owner-user>
# Set RAT_DRYRUN=1 to print the pfctl calls instead of running them.
MODE="$1"
PFCTL="${RAT_PFCTL:-/sbin/pfctl}"
ANCHOR="com.apple/rat"

run() { if [ -n "$RAT_DRYRUN" ]; then echo "$@"; else "$@" >/dev/null 2>&1; fi; }

if [ "$MODE" = "snapshot" ]; then
  OUT="$2"; OWNER="$3"
  TMP="$OUT.tmp"
  { /usr/sbin/lsof -nP -i -F pPnT 2>/dev/null; echo "#PS"; /bin/ps -axo pid=,comm= 2>/dev/null; } > "$TMP" || exit 0
  [ -n "$OWNER" ] && /usr/sbin/chown "$OWNER" "$TMP" 2>/dev/null
  /bin/chmod 600 "$TMP"
  /bin/mv -f "$TMP" "$OUT"
  exit 0
fi

LIST="$2"
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
