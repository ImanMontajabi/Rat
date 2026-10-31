#!/bin/sh
# Live check of the root enforcer (rat-enforcerd). Needs root (pfctl) and network access:
#
#   sudo scripts/verify-blocking.sh [path-to-rat-enforcerd]
#
# It runs the real daemon against a throw-away deny list and its own pf anchor ("com.apple/rat-verify"), so a
# running Rat helper is left alone. /usr/bin/curl is the denied app, python3 and dig are the allowed ones.
#
#  1. Mid-stream: a denied curl and an allowed python3 download from the SAME server address. curl is denied after
#     both are running. curl's stream must stop for good after reading what was already in its socket
#     buffer (measured at the deny, see `midstream`); python3 must keep downloading, and DNS to 1.1.1.1 and
#     8.8.8.8 must keep working (dig). The anchor must hold no address table and no pass rule, and the legacy
#     blocklist file must be gone.
#  2. Fresh processes: brand-new curls to unknown servers. This is the hard case (the ports are loaded after the
#     socket exists), so leaks are counted and reported, not hidden.
#  3. Local proxy (scripts/test-proxy.py on 127.0.0.1, HTTP CONNECT and SOCKS5): the daemon must publish the real
#     destinations of curl's proxied requests (example.com:443, www.wikipedia.org:443) with the proxy process,
#     and once curl is denied, its connections through the proxy must be cut on lo0 (mid-stream and fresh), while
#     an allowed python3 keeps downloading through the same proxy.
#  4. Rules for one process and one connection (deny-rules.json, followed by the daemon itself, 1.5.0): a ✗ on
#     curl as a process of the macOS row cuts its stream and fresh curls while python3 keeps downloading; a ✗ on
#     one connection (curl to one server address, then to one server by the name Rat gave it) cuts only that
#     connection, and curl to other servers keeps working.
#  5. Only through a VPN (1.6.0, #45; `conditionalRules`): curl may connect only through a VPN tunnel. A curl bound
#     to the Wi-Fi or Ethernet address (`--interface`), which works without the rule, is cut whether or not a VPN is
#     up (skipped when it does not work without the rule: a VPN's own kill switch); with a VPN carrying the Internet a
#     plain curl goes through it and works, without one it is cut. dig keeps resolving.
#  6. Servers in one country (#45; `Rule.country`, `DaemonRules.geoDatabase`): curl is denied the country the
#     offline City database places $HOST in (looked up with the daemon's own `--country`). Its running download is
#     cut and fresh curls to that server are blocked, while curl to a server in another country keeps working and
#     python3 keeps downloading from the denied country; the anchor still holds ports only. With no readable
#     database the daemon cuts nothing for a country. The database is the one next to the daemon in Rat.app, else
#     RAT_GEOIP_DB, else the repo's App/Vendor copy.
set -u
[ "$(id -u)" = 0 ] || { echo "run with sudo" >&2; exit 2; }
ROOT=$(cd "$(dirname "$0")/.." && pwd)
DAEMON="${1:-$(ls -d "$HOME"/Library/Developer/Xcode/DerivedData/Rat-*/Build/Products/Debug/Rat.app/Contents/MacOS/rat-enforcerd 2>/dev/null | head -1)}"
[ -x "$DAEMON" ] || DAEMON="$ROOT/RatFilter/.build/debug/rat-enforcerd"
[ -x "$DAEMON" ] || { echo "rat-enforcerd not found; pass its path" >&2; exit 2; }

ANCHOR="com.apple/rat-verify"
WORK=$(mktemp -d)
: > "$WORK/denied.txt"
echo '{}' > "$WORK/deny-rules.json"
echo "1.1.1.1" > "$WORK/legacy-blocklist.txt"   # what 1.0.3 left behind; the daemon must delete it
FAIL=0
size() { /usr/bin/stat -f %z "$1" 2>/dev/null || echo 0; }
# Local port of a process's established TCP connection, and the bytes waiting in its receive queue (netstat's
# Recv-Q) for that connection to a server (netstat's "address.port"; $IP.443 unless given).
tcp_port() { /usr/sbin/lsof -a -p "$1" -iTCP -sTCP:ESTABLISHED -n -P -Fn 2>/dev/null | sed -n 's/^n.*:\([0-9]*\)->.*/\1/p' | head -1; }
recvq() {
  [ -n "$1" ] && /usr/sbin/netstat -anp tcp | awk -v lp=".$1" -v r="${2:-$IP.443}" '$5 == r && substr($4, length($4) - length(lp) + 1) == lp { print $2; exit }'
}
# pf states of a local port: pf looks up its state table before any rule, so a state another ruleset kept would
# carry the flow past Rat's anchor (the daemon kills those it finds after loading a port, `pfctl -k local -k remote`).
port_states() { /sbin/pfctl -s states 2>/dev/null | grep -cE "[:.\[]$1[] ]" ; }
all_states() { /sbin/pfctl -s info 2>/dev/null | awk '/current entries/ { print $3 }'; }
# midstream <curl's server, netstat's "address.port"> <curl pid> <curl file> <python3 file> <command that denies curl…>
# A rate-limited curl keeps reading what already arrived in its socket buffer after the cut (macOS grows it to
# several MB; at 400 KB/s 4 MB takes 10 s), so growth alone proves nothing. The cut is proven when curl stops for
# good having read no more than the buffer held at the deny (+64 KB for packets in flight while pf loads), and
# python3 downloading from the same server keeps going.
midstream() {
  mremote=$1; mpid=$2; mout=$3; mpy=$4; shift 4
  LP=$(tcp_port "$mpid"); Q=$(recvq "$LP" "$mremote")
  # Without the buffer there is nothing to compare with: that is a failure of the test, not a pass or a leak.
  [ -n "$Q" ] || { echo "  FAIL could not read curl's socket buffer (port ${LP:-?} to $mremote)"; FAIL=1; Q=0; }; SB=$(port_states "${LP:-0}")
  M1=$(size "$mout"); P1=$(size "$mpy")
  "$@"
  last=$M1; still=0; steps=0
  while [ $steps -lt 40 ]; do
    sleep 0.5; steps=$((steps + 1)); now=$(size "$mout")
    if [ "$now" = "$last" ]; then still=$((still + 1)); [ $still -ge 3 ] && break; else still=0; last=$now; fi
  done
  P2=$(size "$mpy"); sleep 1.5; M3=$(size "$mout"); P3=$(size "$mpy")
  echo "  curl read +$((last - M1)) bytes after the deny; $Q were already in its socket buffer; it stopped after $(( (steps - still) / 2 )) s"
  echo "  pf states for curl's port ${LP:-?}: $SB before the deny, $(port_states "${LP:-0}") after (all states: $(all_states))"
  if [ $still -ge 3 ] && [ "$M3" = "$last" ] && [ $((last - M1)) -le $((Q + 65536)) ]; then echo "  ok denied curl stream is dead (only its buffer was read)"
  else echo "  FAIL denied curl kept downloading beyond what was buffered"; FAIL=1; fi
  [ "$P3" -gt "$P2" ] && echo "  ok allowed python3 kept downloading from the same address (+$((P3 - P1)) bytes)" || { echo "  FAIL allowed python3 was interrupted (collateral)"; FAIL=1; }
}
deny_curl() { echo "/usr/bin/curl" > "$WORK/denied.txt"; }

RAT_TRACE=${RAT_TRACE:-} "$DAEMON" --denied "$WORK/denied.txt" --blocklist "$WORK/legacy-blocklist.txt" --anchor "$ANCHOR" \
  --proxied "$WORK/proxied.json" --owner-uid "$(id -u)" --rules "$WORK/deny-rules.json" &
DPID=$!
PXPID=
cleanup() {
  kill -9 $APID $BPID $PXPID 2>/dev/null; kill $DPID 2>/dev/null
  /usr/bin/pkill -9 -f "[s]cripts/test-proxy.py ${PPORT:-18089}" 2>/dev/null   # /usr/bin/python3 runs the interpreter as a child
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

midstream "$IP.443" $APID "$WORK/a.out" "$WORK/b.out" deny_curl   # deny curl, mid-stream
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

kill -9 $APID $BPID 2>/dev/null; wait $APID $BPID 2>/dev/null; APID=; BPID=

echo "== phase 2, fresh curl processes to servers never seen (hard case)"
echo "  pf states before: $(all_states)"
TOTAL=0; LEAKS=0
for u in https://www.google.com https://www.youtube.com https://www.wikipedia.org https://www.cloudflare.com https://example.com; do
  for fam in -4 -6 ""; do
    TOTAL=$((TOTAL + 1))
    r=$(/usr/bin/curl -s -o /dev/null --connect-timeout 3 --max-time 6 -w '%{http_code} %{size_download}' $fam "$u" 2>/dev/null)
    [ "${r#* }" = 0 ] && [ "${r% *}" = 000 ] || LEAKS=$((LEAKS + 1))
  done
done
echo "  $((TOTAL - LEAKS))/$TOTAL fresh requests blocked completely (pf states after: $(all_states))"

echo "== phase 3, local proxy: unmasking and blocking through 127.0.0.1"
: > "$WORK/denied.txt"; sleep 1
PPORT=18089
/usr/bin/python3 -I "$ROOT/scripts/test-proxy.py" $PPORT &
PXPID=$!
sleep 1
r1=$(/usr/bin/curl -s -o /dev/null --max-time 10 -w '%{http_code}' --proxy "http://127.0.0.1:$PPORT" https://example.com)
r2=$(/usr/bin/curl -s -o /dev/null --max-time 10 -w '%{http_code}' --socks5-hostname "127.0.0.1:$PPORT" https://www.wikipedia.org)
echo "  allowed curl through the proxy: CONNECT example.com -> $r1, SOCKS5 www.wikipedia.org -> $r2"
{ [ "$r1" = 200 ] && [ "$r2" = 200 ]; } || { echo "  FAIL proxy requests did not work while allowed"; FAIL=1; }
sleep 1.5
/usr/bin/python3 -I - "$WORK/proxied.json" <<'PY' || FAIL=1
import json, sys
flows = json.load(open(sys.argv[1]))["flows"]
seen = {(f["kind"], f["host"], f["port"]) for f in flows if f["clientPath"] == "/usr/bin/curl"}
for f in flows:
    print(f"  unmasked: {f['clientPath'].rsplit('/', 1)[-1]} -> {f['host']}:{f['port']} ({f['kind']}) via {str(f.get('proxyPath')).rsplit('/', 1)[-1]} 127.0.0.1:{f['proxyPort']}")
ok = ("HTTP CONNECT", "example.com", 443) in seen and ("SOCKS5", "www.wikipedia.org", 443) in seen
ok = ok and all(f.get("proxyPID") for f in flows)
print("  ok both destinations and the proxy process were seen on lo0" if ok else "  FAIL destinations missing from the daemon's flow file")
sys.exit(0 if ok else 1)
PY
perm=$(/usr/bin/stat -f %Lp "$WORK/proxied.json" 2>/dev/null)
[ "$perm" = 600 ] && echo "  ok flow file is private (mode 600)" || { echo "  FAIL flow file mode $perm"; FAIL=1; }

/usr/bin/curl -s --limit-rate 400k --proxy "http://127.0.0.1:$PPORT" -o "$WORK/pa.out" "https://$HOST/files/1Gb.dat" &
APID=$!
/usr/bin/python3 -I - "$PPORT" "$HOST" "$WORK/pb.out" <<'PY' &
import socket, ssl, sys, time
port, host, out = int(sys.argv[1]), sys.argv[2], sys.argv[3]
s = socket.create_connection(("127.0.0.1", port), timeout=10)
s.sendall(f"CONNECT {host}:443 HTTP/1.1\r\nHost: {host}:443\r\n\r\n".encode())
head = b""
while b"\r\n\r\n" not in head: head += s.recv(1)
c = ssl.create_default_context().wrap_socket(s, server_hostname=host)
c.sendall(f"GET /files/1Gb.dat HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode())
with open(out, "wb") as f:
    while True:
        d = c.recv(16384)
        if not d: break
        f.write(d); f.flush(); time.sleep(0.04)
PY
BPID=$!
sleep 4
A1=$(size "$WORK/pa.out"); B1=$(size "$WORK/pb.out")
echo "  mid-stream through the proxy, before deny: curl $A1 bytes, python3 $B1 bytes"
{ [ "$A1" -gt 0 ] && [ "$B1" -gt 0 ]; } || { echo "  could not start both proxied downloads"; FAIL=1; }
# curl's socket is to the proxy on lo0, with a loopback buffer of its own.
midstream "127.0.0.1.$PPORT" $APID "$WORK/pa.out" "$WORK/pb.out" deny_curl
echo "  anchor rules while curl is denied:"
/sbin/pfctl -a "$ANCHOR" -s rules 2>/dev/null | grep 'on lo0' | sed 's/^/    /'
/sbin/pfctl -a "$ANCHOR" -s rules 2>/dev/null | grep -q 'on lo0' && echo "  ok loopback rules present" || { echo "  FAIL no loopback rule"; FAIL=1; }
/sbin/pfctl -a "$ANCHOR" -s rules 2>/dev/null | grep -qE '^pass|<' && { echo "  FAIL pass rule or table"; FAIL=1; }
kill -9 $APID $BPID 2>/dev/null; wait $APID $BPID 2>/dev/null; APID=; BPID=

PT=0; PL=0
for i in 1 2 3 4 5; do
  for mode in connect socks; do
    PT=$((PT + 1))
    if [ $mode = connect ]; then r=$(/usr/bin/curl -s -o /dev/null --max-time 6 -w '%{http_code} %{size_download}' --proxy "http://127.0.0.1:$PPORT" https://example.com)
    else r=$(/usr/bin/curl -s -o /dev/null --max-time 6 -w '%{http_code} %{size_download}' --socks5-hostname "127.0.0.1:$PPORT" https://www.wikipedia.org); fi
    [ "${r#* }" = 0 ] && [ "${r% *}" = 000 ] || PL=$((PL + 1))
  done
done
echo "  $((PT - PL))/$PT fresh denied curls through the proxy blocked completely"
r=$(/usr/bin/python3 -I - "$PPORT" <<'PY'
import socket, sys
s = socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=10)
s.sendall(b"CONNECT example.com:443 HTTP/1.1\r\n\r\n")
print(s.recv(64).split(b"\r\n")[0].decode())
PY
)
case "$r" in *200*) echo "  ok allowed python3 still gets through the proxy ($r)";; *) echo "  FAIL allowed python3 through the proxy: $r"; FAIL=1;; esac
kill $PXPID 2>/dev/null; /usr/bin/pkill -9 -f "[s]cripts/test-proxy.py $PPORT"; PXPID=

echo "== phase 4, rules the daemon follows itself: one process, one connection"
: > "$WORK/denied.txt"; sleep 1
# deny-rules.json as Rat writes it (DaemonRules): the rules, and the names Rat gave the servers. Written next to
# it first and then renamed over it, as Rat does: the rename is the moment of the deny. A mid-stream check stages
# the file before it reads curl's buffer and passes only the rename as its deny, so python3's start (about 60 ms,
# during which a buffer that is not full yet keeps filling) is not counted against the daemon.
stage_rules() {  # stage_rules <json array of rules> [<json object of names>]
  /usr/bin/python3 -I -c 'import json, sys; json.dump({"version": 1, "rules": json.loads(sys.argv[1]), "names": json.loads(sys.argv[2]) or {}, "signatures": {}, "localRanges": ""}, open(sys.argv[3] + ".tmp", "w"))' \
    "$1" "${2:-null}" "$WORK/deny-rules.json"
}
apply_rules() { mv "$WORK/deny-rules.json.tmp" "$WORK/deny-rules.json"; }
rules() { stage_rules "$@" && apply_rules; }
fresh() {  # fresh <count> <curl args…>: how many fresh curls got nothing at all
  n=$1; shift; got=0
  for i in $(seq "$n"); do
    r=$(/usr/bin/curl -s -o /dev/null --connect-timeout 3 --max-time 6 -w '%{http_code} %{size_download}' "$@" 2>/dev/null)
    [ "${r#* }" = 0 ] && [ "${r% *}" = 000 ] && got=$((got + 1))
  done
  echo "$got"
}
CURL_PROCESS='[{"verdict": "deny", "processPath": "macOS", "executable": "/usr/bin/curl", "listLevel": "process"}]'

/usr/bin/curl -s --limit-rate 400k --resolve "$HOST:443:$IP" -o "$WORK/ra.out" "https://$HOST/files/1Gb.dat" &
APID=$!
/usr/bin/python3 - "$IP" "$HOST" "$WORK/rb.out" <<'PY' &
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
A1=$(size "$WORK/ra.out"); B1=$(size "$WORK/rb.out")
echo "  4a. curl as a process of macOS denied mid-stream (before: curl $A1 bytes, python3 $B1 bytes)"
stage_rules "$CURL_PROCESS"
midstream "$IP.443" $APID "$WORK/ra.out" "$WORK/rb.out" apply_rules
kill -9 $APID $BPID 2>/dev/null; wait $APID $BPID 2>/dev/null; APID=; BPID=
RP=$(fresh 10 https://example.com)
echo "  $RP/10 fresh curls blocked completely by the process rule (pf states: $(all_states))"
[ "$RP" -gt 0 ] || { echo "  FAIL no fresh curl was blocked by the process rule"; FAIL=1; }
/sbin/pfctl -a "$ANCHOR" -s rules 2>/dev/null | grep -qE '^pass|<' && { echo "  FAIL pass rule or table"; FAIL=1; } || echo "  ok anchor: ports only"

echo "  4b. one connection denied: curl -> $IP:443 (TCP)"
rules "[{\"verdict\": \"deny\", \"processPath\": \"macOS\", \"executable\": \"/usr/bin/curl\", \"listLevel\": \"connection\", \"remoteAddress\": \"$IP\", \"ports\": [443, 443], \"proto\": \"tcp\"}]"
sleep 0.5
RC=$(fresh 10 --resolve "$HOST:443:$IP" "https://$HOST/")
echo "  $RC/10 fresh curls to $IP blocked completely"
[ "$RC" -gt 0 ] || { echo "  FAIL no curl to the denied connection was blocked"; FAIL=1; }
r=$(/usr/bin/curl -s -o /dev/null --connect-timeout 4 --max-time 8 -w '%{http_code}' -4 https://example.com)
[ "$r" = 200 ] && echo "  ok curl to another server still works (example.com -> 200)" || { echo "  FAIL curl to another server -> $r (collateral)"; FAIL=1; }

echo "  4c. one connection denied by the name Rat gave it: curl -> $HOST:443"
rules "[{\"verdict\": \"deny\", \"processPath\": \"macOS\", \"executable\": \"/usr/bin/curl\", \"listLevel\": \"connection\", \"remoteHost\": \"$HOST\", \"ports\": [443, 443], \"proto\": \"tcp\"}]" "{\"$IP\": \"$HOST\"}"
sleep 0.5
RN=$(fresh 10 --resolve "$HOST:443:$IP" "https://$HOST/")
echo "  $RN/10 fresh curls to $HOST blocked completely"
[ "$RN" -gt 0 ] || { echo "  FAIL no curl to the denied name was blocked"; FAIL=1; }
r=$(/usr/bin/curl -s -o /dev/null --connect-timeout 4 --max-time 8 -w '%{http_code}' -4 https://example.com)
[ "$r" = 200 ] && echo "  ok curl to another server still works (example.com -> 200)" || { echo "  FAIL curl to another server -> $r (collateral)"; FAIL=1; }
echo '{}' > "$WORK/deny-rules.json"

echo "== phase 5, only through a VPN"
VPN_ONLY='[{"verdict": "deny", "processPath": "macOS", "executable": "/usr/bin/curl", "requireVPN": true}]'
PHYS=; for i in en0 en1 en2 en3 en4 en5; do /usr/sbin/ipconfig getifaddr "$i" >/dev/null 2>&1 && { PHYS=$i; break; }; done
FULL=$(/sbin/route -n get 1.1.1.1 2>/dev/null | awk '/interface:/ { print $2 }')
# Without the rule a curl outside the tunnel must work, or a block proves nothing: a VPN's own firewall (Windscribe's
# with its kill switch on) already stops everything outside the tunnel.
OUTSIDE=
if [ -n "$PHYS" ]; then
  r=$(/usr/bin/curl -s -o /dev/null --connect-timeout 4 --max-time 8 -w '%{http_code}' --interface "$PHYS" https://example.com)
  [ "$r" = 200 ] && OUTSIDE=1 || echo "  note: without the rule a curl bound to $PHYS already fails ($r): something else blocks traffic outside the tunnel"
fi
/usr/bin/python3 -I -c 'import json, sys; json.dump({"version": 1, "rules": [], "conditionalRules": json.loads(sys.argv[1]), "names": {}, "signatures": {}, "localRanges": ""}, open(sys.argv[2] + ".tmp", "w"))' \
  "$VPN_ONLY" "$WORK/deny-rules.json" && apply_rules
sleep 0.5
if [ -n "$OUTSIDE" ]; then
  RW=$(fresh 10 --interface "$PHYS" https://example.com)
  echo "  $RW/10 fresh curls bound to $PHYS ($(/usr/sbin/ipconfig getifaddr "$PHYS")) blocked completely"
  [ "$RW" -gt 0 ] || { echo "  FAIL no curl outside the tunnel was blocked"; FAIL=1; }
else RW=; echo "  skip: no curl outside the tunnel to cut (no Wi-Fi or Ethernet address, or it is blocked already)"; fi
case "$FULL" in
  utun*|ipsec*|ppp*|tun*|wg*)
    r=$(/usr/bin/curl -s -o /dev/null --connect-timeout 4 --max-time 8 -w '%{http_code}' https://example.com)
    [ "$r" = 200 ] && echo "  ok through the VPN ($FULL) curl works (example.com -> 200)" || { echo "  FAIL curl through the VPN ($FULL) -> $r"; FAIL=1; } ;;
  *)
    RV=$(fresh 10 https://example.com)
    echo "  no VPN carries the Internet (route via ${FULL:-?}): $RV/10 plain curls blocked completely"
    [ "$RV" -gt 0 ] || { echo "  FAIL no curl was blocked without a VPN"; FAIL=1; } ;;
esac
/usr/bin/dig +short +time=2 +tries=1 example.com @1.1.1.1 | grep -q . && echo "  ok DNS (dig @1.1.1.1)" || { echo "  FAIL DNS to 1.1.1.1"; FAIL=1; }
/sbin/pfctl -a "$ANCHOR" -s rules 2>/dev/null | grep -qE '^pass|<' && { echo "  FAIL pass rule or table"; FAIL=1; } || echo "  ok anchor: ports only"
echo '{}' > "$WORK/deny-rules.json"

echo "== phase 6, servers in one country"
GEODB="$(dirname "$DAEMON")/../Resources/Vendor/dbip-city-lite.mmdb"
[ -r "$GEODB" ] || GEODB="${RAT_GEOIP_DB:-$ROOT/App/Vendor/dbip-city-lite.mmdb}"
CC=; [ -r "$GEODB" ] && CC=$("$DAEMON" --country "$IP" --geoip "$GEODB" 2>/dev/null)
OTHER_IP=$(/usr/bin/dig +short +time=3 +tries=1 A example.com | grep -E '^[0-9.]+$' | head -1)
OTHER_CC=; [ -n "$CC" ] && [ -n "$OTHER_IP" ] && OTHER_CC=$("$DAEMON" --country "$OTHER_IP" --geoip "$GEODB" 2>/dev/null)
country_rules() {  # country_rules <database path>: curl denied the servers in $CC
  /usr/bin/python3 -I -c 'import json, sys; json.dump({"version": 1, "rules": [], "conditionalRules": [{"verdict": "deny", "processPath": "macOS", "executable": "/usr/bin/curl", "country": sys.argv[1]}], "names": {}, "signatures": {}, "localRanges": "", "geoDatabase": sys.argv[2]}, open(sys.argv[3] + ".tmp", "w"))' \
    "$CC" "$1" "$WORK/deny-rules.json"
}
if [ -z "$CC" ] || [ "$CC" = - ]; then
  echo "  FAIL no country for $IP (database: $GEODB)"; FAIL=1; RK=
else
  echo "  $HOST ($IP) is in $CC by $GEODB; example.com ($OTHER_IP) in ${OTHER_CC:-?}"
  /usr/bin/curl -s --limit-rate 400k --resolve "$HOST:443:$IP" -o "$WORK/ka.out" "https://$HOST/files/1Gb.dat" &
  APID=$!
  /usr/bin/python3 - "$IP" "$HOST" "$WORK/kb.out" <<'PY' &
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
  echo "  6a. curl denied the servers in $CC mid-stream"
  country_rules "$GEODB"
  midstream "$IP.443" $APID "$WORK/ka.out" "$WORK/kb.out" apply_rules
  kill -9 $APID $BPID 2>/dev/null; wait $APID $BPID 2>/dev/null; APID=; BPID=
  RK=$(fresh 10 --resolve "$HOST:443:$IP" "https://$HOST/")
  echo "  $RK/10 fresh curls to $IP ($CC) blocked completely"
  [ "$RK" -gt 0 ] || { echo "  FAIL no curl to a server in $CC was blocked"; FAIL=1; }
  if [ -n "$OTHER_CC" ] && [ "$OTHER_CC" != - ] && [ "$OTHER_CC" != "$CC" ]; then
    r=$(/usr/bin/curl -s -o /dev/null --connect-timeout 4 --max-time 8 -w '%{http_code}' --resolve "example.com:443:$OTHER_IP" https://example.com)
    [ "$r" = 200 ] && echo "  ok curl to a server in $OTHER_CC still works (example.com -> 200)" || { echo "  FAIL curl to a server in $OTHER_CC -> $r (collateral)"; FAIL=1; }
  else echo "  skip: example.com is not in another country the database knows (${OTHER_CC:-?})"; fi
  /usr/bin/dig +short +time=2 +tries=1 example.com @1.1.1.1 | grep -q . && echo "  ok DNS (dig @1.1.1.1)" || { echo "  FAIL DNS to 1.1.1.1"; FAIL=1; }
  /sbin/pfctl -a "$ANCHOR" -s rules 2>/dev/null | grep -qE '^pass|<' && { echo "  FAIL pass rule or table"; FAIL=1; } || echo "  ok anchor: ports only"

  echo "  6b. the same rule with no readable database: nothing is cut for a country"
  echo '{}' > "$WORK/deny-rules.json"; sleep 7   # the ports of 6a are held a few seconds (packets in flight)
  country_rules "$WORK/no-such.mmdb" && apply_rules; sleep 0.5
  RU=$(fresh 3 --resolve "$HOST:443:$IP" "https://$HOST/")
  [ "$RU" = 0 ] && echo "  ok 0/3 curls blocked" || { echo "  FAIL $RU/3 curls blocked without a database"; FAIL=1; }
fi
echo '{}' > "$WORK/deny-rules.json"

echo "== deny list and rules emptied: curl must work again"
: > "$WORK/denied.txt"; sleep 7
r=$(/usr/bin/curl -s -o /dev/null --connect-timeout 4 --max-time 8 -w '%{http_code}' https://example.com)
[ "$r" = 200 ] && echo "  ok example.com -> 200" || { echo "  FAIL example.com -> $r"; FAIL=1; }

[ "$FAIL" = 0 ] && echo "PASS (fresh-process leak rate: $LEAKS/$TOTAL direct, ${PL:-?}/${PT:-?} through the proxy; rules: process $((10 - ${RP:-0}))/10, connection $((10 - ${RC:-0}))/10, by name $((10 - ${RN:-0}))/10, outside the VPN $([ -n "${RW:-}" ] && echo "$((10 - RW))/10" || echo skipped), country $([ -n "${RK:-}" ] && echo "$((10 - RK))/10" || echo skipped))" || echo "FAIL"
exit "$FAIL"
