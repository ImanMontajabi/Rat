#!/bin/sh
# What Rat is enforcing right now, read-only. Run with sudo to include the live pf rules.
#   scripts/rat-status.sh        # deny list and the helper's status
#   sudo scripts/rat-status.sh   # plus the rules in the com.apple/rat anchor
SUP="${RAT_SUPPORT:-$(eval echo ~${SUDO_USER:-$USER})/Library/Application Support/com.imanmontajabi.Rat}"
echo "== denied-apps.txt (written by Rat when an app is denied)"
if [ -s "$SUP/denied-apps.txt" ]; then sed 's/^/  /' "$SUP/denied-apps.txt"; else echo "  (empty: no app is denied)"; fi
echo "== rat-enforcerd status"
ST=/var/run/com.imanmontajabi.rat.enforcer.json
if [ -r "$ST" ]; then
  /usr/bin/python3 - "$ST" <<'PY'
import json, sys, time
s = json.load(open(sys.argv[1]))
age = time.time() - s["updated"]
print(f"  daemon pid {s['pid']}, updated {age:.0f} s ago{'  (STALE: daemon not running?)' if age > 10 else ''}")
print(f"  pf enabled: {s['pfEnabled']}   com.apple anchors evaluated: {s['anchorHooked']}   blocked ports: {s['blockedPorts']}")
for app, a in sorted(s["deniedApps"].items()):
    print(f"  {a['processes']:3} processes, {a['ports']:3} open connections cut   {app}")
if not s["deniedApps"]:
    print("  no process of a denied app is running")
PY
else
  echo "  no status file: the helper (1.0.5 or later) is not installed or not running"
fi
if [ "$(id -u)" = 0 ]; then
  echo "== pfctl -a com.apple/rat -s rules"
  /sbin/pfctl -a com.apple/rat -s rules 2>/dev/null | sed 's/^/  /'
  echo "== pfctl -a com.apple/rat -s Tables (must be empty)"
  /sbin/pfctl -a com.apple/rat -s Tables 2>/dev/null | sed 's/^/  /'
else
  echo "(run with sudo to list the live pf rules)"
fi
