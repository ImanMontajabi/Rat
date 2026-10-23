#!/bin/sh
# Rat root helper, installed root-owned as a LaunchDaemon (opt-in, with the user's administrator password).
#
#   snapshot - runs every few seconds: lists every process's sockets (lsof as root) so Rat can show
#              processes of other users and system daemons that an unprivileged app cannot see.
#
# Blocking is done by rat-enforcerd, not by this script. This script never touches the firewall.
#
# Usage: rat-pf-helper snapshot <output-file> <owner-user>
if [ "$1" = "snapshot" ]; then
  OUT="$2"; OWNER="$3"
  TMP="$OUT.tmp"
  { /usr/sbin/lsof -nP -i -F pPnT 2>/dev/null; echo "#PS"; /bin/ps -axo pid=,comm= 2>/dev/null; } > "$TMP" || exit 0
  [ -n "$OWNER" ] && /usr/sbin/chown "$OWNER" "$TMP" 2>/dev/null
  /bin/chmod 600 "$TMP"
  /bin/mv -f "$TMP" "$OUT"
  exit 0
fi
echo "usage: rat-pf-helper snapshot <output-file> <owner-user>" >&2
exit 64
