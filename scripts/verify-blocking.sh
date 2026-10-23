#!/bin/sh
# Live check of the root enforcer: a denied process must transfer zero bytes, an allowed one must work.
# Needs root (pfctl). Uses its own pf anchor ("com.apple/rat-verify") so a running Rat helper is left alone.
#
#   sudo scripts/verify-blocking.sh [path-to-rat-enforcerd]
#
# It runs the real daemon against a throw-away deny list that names /usr/bin/curl, then fetches several
# multi-address sites (Google, YouTube, ...) over IPv4, IPv6, HTTP/2 and HTTP/3-capable hosts with curl.
set -u
[ "$(id -u)" = 0 ] || { echo "run with sudo" >&2; exit 2; }
ROOT=$(cd "$(dirname "$0")/.." && pwd)
DAEMON="${1:-$(ls -d "$HOME"/Library/Developer/Xcode/DerivedData/Rat-*/Build/Products/Debug/Rat.app/Contents/MacOS/rat-enforcerd 2>/dev/null | head -1)}"
[ -x "$DAEMON" ] || DAEMON="$ROOT/RatFilter/.build/debug/rat-enforcerd"
[ -x "$DAEMON" ] || { echo "rat-enforcerd not found; pass its path" >&2; exit 2; }

ANCHOR="com.apple/rat-verify"
WORK=$(mktemp -d)
echo /usr/bin/curl > "$WORK/denied.txt"
: > "$WORK/blocklist.txt"
URLS="https://www.google.com https://www.youtube.com https://www.wikipedia.org https://www.cloudflare.com https://example.com"
FAIL=0

fetch() { # url, extra curl args -> prints "code bytes"
  /usr/bin/curl -s -o /dev/null --connect-timeout 3 --max-time 6 -w '%{http_code} %{size_download}' "$@" 2>/dev/null
}

echo "== baseline (no enforcer running): curl must work"
for u in $URLS; do
  r=$(fetch "$u"); echo "  $u -> $r"
  case "$r" in 000*) echo "  (network unreachable here; cannot verify)"; rm -rf "$WORK"; exit 3;; esac
done

echo "== start enforcer ($DAEMON)"
RAT_TRACE=${RAT_TRACE:-} "$DAEMON" --denied "$WORK/denied.txt" --blocklist "$WORK/blocklist.txt" --anchor "$ANCHOR" &
PID=$!
cleanup() { kill "$PID" 2>/dev/null; wait "$PID" 2>/dev/null; /sbin/pfctl -a "$ANCHOR" -F all >/dev/null 2>&1; rm -rf "$WORK"; }
trap cleanup EXIT INT TERM
sleep 1

# Phase 1: nothing is known about the servers. Every curl is a brand-new process, which is the hardest case: the
# daemon sees it within ~10 ms and must load its ports before the server's SYN-ACK arrives. Leaks here are counted,
# not hidden; a long-running browser benefits from the address layer below after its first connections.
echo "== phase 1, servers unknown, fresh process per request (port layer)"
TOTAL=0; LEAKS=0
for u in $URLS; do
  for fam in -4 -6 ""; do
    TOTAL=$((TOTAL + 1))
    r=$(fetch $fam "$u"); code=${r% *}; bytes=${r#* }
    if [ "$bytes" != 0 ] || [ "$code" != 000 ]; then echo "  leak ${fam:--} $u -> $r"; LEAKS=$((LEAKS + 1)); fi
  done
done
echo "  $((TOTAL - LEAKS))/$TOTAL requests blocked"

# An allowed app must not suffer: python3 (another path) talks to the same sites while /usr/bin/curl is denied.
echo "== other app, same sites, must work while curl is denied"
for u in $URLS; do
  r=$(/usr/bin/python3 -c 'import sys,urllib.request as r,urllib.error as e
try: print(r.urlopen(sys.argv[1], timeout=6).status)
except e.HTTPError as x: print(x.code)' "$u" 2>/dev/null)
  case "$r" in [1-5][0-9][0-9]) echo "  ok $u -> $r";; *) echo "  COLLATERAL $u -> ${r:-failed}"; FAIL=1;; esac
done

# Phase 2: servers Rat has already seen are in the address table, so nothing may get through, deterministically.
echo "== phase 2, servers known (address layer): zero bytes required"
PIN=""
: > "$WORK/blocklist.txt"
for u in $URLS; do
  h=${u#https://}
  # all addresses go into the table; two per site (one IPv4, one IPv6) are then fetched with the address pinned
  addrs=$(/usr/bin/dscacheutil -q host -a name "$h" 2>/dev/null | awk '/^(ip_address|ipv6_address):/ {print $2}' | sort -u)
  for ip in $addrs; do
    echo "$ip" >> "$WORK/blocklist.txt"
  done
  for ip in $(echo "$addrs" | grep -v : | head -1) $(echo "$addrs" | grep : | head -1); do
    PIN="$PIN $h:$ip"
  done
done
touch "$WORK/blocklist.txt"; sleep 1
for pin in $PIN; do
  h=${pin%%:*}; ip=${pin#*:}
  r=$(fetch --resolve "$h:443:$ip" "https://$h"); code=${r% *}; bytes=${r#* }
  if [ "$bytes" != 0 ] || [ "$code" != 000 ]; then echo "  LEAK $h via $ip -> $r"; FAIL=1; else echo "  blocked $h via $ip"; fi
done

echo "== rules in the anchor"
/sbin/pfctl -a "$ANCHOR" -s rules 2>/dev/null | sed 's/^/  /' | head -8

echo "== deny list emptied: curl must work again"
: > "$WORK/denied.txt"; : > "$WORK/blocklist.txt"; sleep 7   # ports are held 5 s after their sockets close
r=$(fetch https://example.com); echo "  example.com -> $r"
case "$r" in 200*) ;; *) echo "  did not recover"; FAIL=1;; esac

[ "$FAIL" = 0 ] && echo "PASS: known servers are blocked completely; port layer blocked $((TOTAL - LEAKS))/$TOTAL fresh-process requests" || echo "FAIL"
exit "$FAIL"
