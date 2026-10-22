#!/bin/sh
# Downloads the DB-IP Lite city database (CC BY 4.0, https://db-ip.com/db/download/ip-to-city-lite)
# into App/Vendor/. The ~125 MB file is not committed; the build bundles it into
# Rat.app/Contents/Resources/Vendor/ so lookups work fully offline.
set -e
DEST="$(dirname "$0")/../App/Vendor/dbip-city-lite.mmdb"
[ -f "$DEST" ] && [ -z "$FORCE" ] && { echo "already present: $DEST"; exit 0; }
for offset in 0 1 2; do
  MONTH=$(date -v-"$offset"m +%Y-%m 2>/dev/null || date -d "-$offset month" +%Y-%m)
  URL="https://download.db-ip.com/free/dbip-city-lite-$MONTH.mmdb.gz"
  if curl -fsSL "$URL" -o "$DEST.gz"; then gunzip -f "$DEST.gz"; mv "${DEST%.gz}" "$DEST" 2>/dev/null || true; echo "downloaded $MONTH"; exit 0; fi
done
echo "could not download the DB-IP database" >&2; exit 1
