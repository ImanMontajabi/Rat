#!/bin/sh
# CPU and memory of the running Rat.app and rat-enforcerd, for the resource line every PR reports (CLAUDE.md).
# Average CPU comes from the processes' CPU time over the window (100% = one core); peak CPU and RSS from a
# sample every second. Reads only `ps`, so it needs no root, and changes nothing.
#
# Usage: scripts/measure-resources.sh [seconds]   (default 60)
set -eu
SECONDS_TO_RUN=${1:-60}
ENFORCER=/Library/PrivilegedHelperTools/com.imanmontajabi.rat.enforcer

# pid of the Rat.app the user runs (the UI-test build has its own bundle id and is not counted), and of the daemon.
rat_pid() { ps -axo pid=,comm= | awk '$2 ~ /\/Rat\.app\/Contents\/MacOS\/Rat$/ { print $1; exit }'; }
enforcer_pid() { ps -axo pid=,comm= | awk -v p="$ENFORCER" '$2 == p { print $1; exit }'; }

# CPU time in seconds from ps's "[[dd-]hh:]mm:ss.ss".
cpu_seconds() {
  ps -o time= -p "$1" 2>/dev/null | awk '{
    n = split($1, a, ":"); s = 0
    for (i = 1; i <= n; i++) { v = a[i]; if (i == 1 && index(v, "-")) { split(v, d, "-"); s = d[1] * 24; v = d[2] }; s = s * 60 + v }
    print s }'
}

RAT=$(rat_pid || true); ENF=$(enforcer_pid || true)
[ -n "$RAT" ] || echo "Rat.app is not running" >&2
[ -n "$ENF" ] || echo "rat-enforcerd is not running (helper not installed?)" >&2
[ -n "$RAT$ENF" ] || exit 1

T0=$(date +%s)
R0=${RAT:+$(cpu_seconds "$RAT")}; E0=${ENF:+$(cpu_seconds "$ENF")}
SAMPLES=$(mktemp)
trap 'rm -f "$SAMPLES"' EXIT
i=0
while [ "$i" -lt "$SECONDS_TO_RUN" ]; do
  for p in $RAT $ENF; do ps -o pid=,%cpu=,rss= -p "$p" 2>/dev/null >> "$SAMPLES" || true; done
  sleep 1
  i=$((i + 1))
done
WALL=$(( $(date +%s) - T0 ))

report() {  # name pid cpu-time-at-start
  [ -n "$2" ] || return 0
  now=$(cpu_seconds "$2")
  awk -v name="$1" -v pid="$2" -v c0="$3" -v c1="$now" -v wall="$WALL" '
    $1 == pid { n++; if ($2 > peak) peak = $2; rss += $3; if ($3 > maxrss) maxrss = $3 }
    END {
      if (n == 0) { printf "%-14s exited during the measurement\n", name; exit }
      printf "%-14s CPU avg %5.1f%%  peak %5.1f%%   RSS avg %6.1f MB  max %6.1f MB   (%d s, pid %s)\n",
        name, (c1 - c0) / wall * 100, peak, rss / n / 1024, maxrss / 1024, wall, pid
    }' "$SAMPLES"
}
report "Rat.app" "$RAT" "${R0:-0}"
report "rat-enforcerd" "$ENF" "${E0:-0}"
