#!/bin/sh
# Downloads the DB-IP Lite databases (CC BY 4.0, https://db-ip.com) into App/Vendor/:
#   dbip-city-lite.mmdb  "IP to City Lite" (~125 MB), server locations for the map
#   dbip-asn-lite.mmdb   "IP to ASN Lite" (~9 MB), the network (organization) a server belongs to
# The files are not committed; the build bundles them into Rat.app/Contents/Resources/Vendor/ so lookups work
# fully offline. FORCE=1 downloads again.
set -e
DIR="$(dirname "$0")/../App/Vendor"
mkdir -p "$DIR"
fetch() {
  KIND="$1"; DEST="$DIR/dbip-$KIND-lite.mmdb"
  [ -f "$DEST" ] && [ -z "$FORCE" ] && { echo "already present: $DEST"; return 0; }
  for offset in 0 1 2; do
    MONTH=$(date -v-"$offset"m +%Y-%m 2>/dev/null || date -d "-$offset month" +%Y-%m)
    URL="https://download.db-ip.com/free/dbip-$KIND-lite-$MONTH.mmdb.gz"
    if curl -fsSL "$URL" -o "$DEST.gz"; then gunzip -f "$DEST.gz"; echo "downloaded $KIND $MONTH"; return 0; fi
  done
  echo "could not download the DB-IP $KIND database" >&2; return 1
}
fetch city
fetch asn
