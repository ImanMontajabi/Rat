#!/bin/sh
# Live check of the root enforcer (rat-enforcerd). Needs root (pfctl) and network access:
#
#   sudo scripts/verify-blocking.sh [path-to-rat-enforcerd]
#
# It runs the real daemon against a throw-away deny list and its own pf anchor ("com.apple/rat-verify"), so a
# running Rat helper is left alone. /usr/bin/curl is the denied app, python3 and dig are the allowed ones.
#
#  1. Mid-stream: a denied curl and an allowed python3 download from the SAME server address. curl is denied after
#     both are running. curl's stream must stop at once; python3 must keep downloading, and DNS to 1.1.1.1 and
#     8.8.8.8 must keep working (dig). The anchor must hold no address table and no pass rule, and the legacy
#     blocklist file must be gone.
#  2. Fresh processes: brand-new curls to unknown servers. This is the hard case (the ports are loaded after the
#     socket exists), so leaks are counted and reported, not hidden.
set -u
[ "$(id -u)" = 0 ] || { echo "run with sudo" >&2; exit 2; }
ROOT=$(cd "$(dirname "$0")/.." && pwd)
DAEMON="${1:-$(ls -d "$HOME"/Library/Developer/Xcode/DerivedData/Rat-*/Build/Products/Debug/Rat.app/Contents/MacOS/rat-enforcerd 2>/dev/null | head -1)}"
[ -x "$DAEMON" ] || DAEMON="$ROOT/RatFilter/.build/debug/rat-enforcerd"
[ -x "$DAEMON" ] || { echo "rat-enforcerd not found; pass its path" >&2; exit 2; }

ANCHOR="com.apple/rat-verify"
WORK=$(mktemp -d)
: > "$WORK/denied.txt"
echo "1.1.1.1" > "$WORK/legacy-blocklist.txt"   # what 1.0.3 left behind; the daemon must delete it
FAIL=0
size() { /usr/bin/stat -f %z "$1" 2>/dev/null || echo 0; }

RAT_TRACE=${RAT_TRACE:-} "$DAEMON" --denied "$WORK/denied.txt" --blocklist "$WORK/legacy-blocklist.txt" --anchor "$ANCHOR" &
DPID=$!
cleanup() {
  kill -9 $APID $BPID 2>/dev/null; kill $DPID 2>/dev/null
  /sbin/pfctl -a "$ANCHOR" -F all >/dev/null 2>&1; rm -rf "$WORK"
}
APID=; BPID=
trap cleanup EXIT INT TERM
sleep 1

echo "== start-up cleanup"
[ ! -e "$WORK/legacy-blocklist.txt" ] && echo "  ok legacy blocklist file deleted" || { echo "  FAIL legacy blocklist file still there"; FAIL=1; }

HOST=proof.ovh.net
IP=$(/usr/bin/dig +short +time=3 +tries=1 A $HOST | grep -E '^[0-9.]+$' | head -1)
[ -n "$IP" ] || { echo "cannot resolve $HOST"; exit 3; }
echo "== phase 1, mid-stream: denied curl and allowed python3 both download from $IP"
/usr/bin/curl -s --limit-rate 400k --resolve "$HOST:443:$IP" -o "$WORK/a.out" "https://$HOST/files/1Gb.dat" &
APID=$!
/usr/bin/python3 - "$IP" "$HOST" "$WORK/b.out" <<'PY' &
import socket, ssl, sys, time
ip, host, out = sys.argv[1:4]
c = ssl.create_default_context().wrap_socket(socket.create_connection((ip, 443), timeout=10), server_hostname=host)
c.sendall(f"GET /files/1Gb.dat HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode())
with open(out, "wb") as f:
    while True:
        d = c.recv(16384)
        if not d: break
        f.write(d); f.flush(); time.sleep(0.04)
PY
BPID=$!
sleep 4
A1=$(size "$WORK/a.out"); B1=$(size "$WORK/b.out")
echo "  before deny: curl $A1 bytes, python3 $B1 bytes"
{ [ "$A1" -gt 0 ] && [ "$B1" -gt 0 ]; } || { echo "  could not start both downloads"; exit 3; }

echo "/usr/bin/curl" > "$WORK/denied.txt"          # deny curl, mid-stream
sleep 0.3
AQ=$(size "$WORK/a.out")
sleep 1.2
A2=$(size "$WORK/a.out"); B2=$(size "$WORK/b.out")
sleep 1.5
AR=$(size "$WORK/a.out")
sleep 1.5
A3=$(size "$WORK/a.out"); B3=$(size "$WORK/b.out")
echo "  curl bytes: 0.3 s after deny +$((AQ - A1)), at 1.5 s +$((A2 - A1)), at 3 s +$((AR - A1))  (curl keeps reading what was already in its socket buffer; the network side is cut at once)"
echo "  1.5 s after deny: curl +$((A2 - A1)) bytes (trickle before the cut), python3 +$((B2 - B1))"
echo "  next 3 s:        curl +$((A3 - A2)) bytes, python3 +$((B3 - B2)) bytes"
[ "$A3" -eq "$A2" ] && echo "  ok denied curl stream is dead" || { echo "  FAIL denied curl kept downloading"; FAIL=1; }
[ "$B3" -gt "$B2" ] && echo "  ok allowed python3 kept downloading from the same address" || { echo "  FAIL allowed python3 was interrupted (collateral)"; FAIL=1; }
kill -0 $APID 2>/dev/null && echo "  note: curl is still running (waiting), not downloading" || echo "  curl exited (connection reset)"

echo "== DNS for allowed apps while curl is denied (1.1.1.1, 8.8.8.8, 9.9.9.9)"
for s in 1.1.1.1 8.8.8.8 9.9.9.9; do
  ok=0
  for i in 1 2 3; do /usr/bin/dig +short +time=2 +tries=1 @$s example.com | grep -qE '^[0-9.]+$' && ok=$((ok + 1)); done
  [ "$ok" = 3 ] && echo "  ok @$s 3/3" || { echo "  FAIL @$s $ok/3"; FAIL=1; }
done

echo "== anchor contents: ports only, no address table, no pass rule"
/sbin/pfctl -a "$ANCHOR" -s rules 2>/dev/null | grep -v '^No ALTQ\|^ALTQ' | sed 's/^/  /'
/sbin/pfctl -a "$ANCHOR" -s Tables 2>/dev/null | grep -q . && { echo "  FAIL anchor has a table"; FAIL=1; } || echo "  ok no tables"
/sbin/pfctl -a "$ANCHOR" -s rules 2>/dev/null | grep -qE '^pass|<' && { echo "  FAIL pass rule or table reference"; FAIL=1; } || echo "  ok no pass rules, no address rules"

kill -9 $APID $BPID 2>/dev/null; APID=; BPID=

echo "== phase 2, fresh curl processes to servers never seen (hard case)"
TOTAL=0; LEAKS=0
for u in https://www.google.com https://www.youtube.com https://www.wikipedia.org https://www.cloudflare.com https://example.com; do
  for fam in -4 -6 ""; do
    TOTAL=$((TOTAL + 1))
    r=$(/usr/bin/curl -s -o /dev/null --connect-timeout 3 --max-time 6 -w '%{http_code} %{size_download}' $fam "$u" 2>/dev/null)
    [ "${r#* }" = 0 ] && [ "${r% *}" = 000 ] || LEAKS=$((LEAKS + 1))
  done
done
echo "  $((TOTAL - LEAKS))/$TOTAL fresh requests blocked completely"

echo "== deny list emptied: curl must work again"
: > "$WORK/denied.txt"; sleep 7
r=$(/usr/bin/curl -s -o /dev/null --connect-timeout 4 --max-time 8 -w '%{http_code}' https://example.com)
[ "$r" = 200 ] && echo "  ok example.com -> 200" || { echo "  FAIL example.com -> $r"; FAIL=1; }

[ "$FAIL" = 0 ] && echo "PASS (fresh-process leak rate: $LEAKS/$TOTAL)" || echo "FAIL"
exit "$FAIL"
