#!/usr/bin/env python3
"""Builds App/Resources/airports.tsv, the IATA code -> place table Rat uses to put a Cloudflare data centre (a WARP
tunnel's exit, such as OpenWarp's `colo=DUS`) on the map. Cloudflare names its data centres by the nearest airport's
IATA code.

Source: OurAirports (https://ourairports.com/data/), airports.csv, released to the public domain. Kept: airports with
a three-letter IATA code that are large or medium, or small with scheduled service; for a code used twice, the larger
airport. One line per code, sorted: IATA <tab> latitude <tab> longitude <tab> ISO country <tab> city.

Usage: scripts/make-airports.py <airports.csv> [out.tsv]   (download: https://davidmegginson.github.io/ourairports-data/airports.csv)
"""
import csv
import re
import sys

RANK = {"large_airport": 3, "medium_airport": 2, "small_airport": 1}
IATA = re.compile(r"^[A-Z]{3}$")
COUNTRY = re.compile(r"^[A-Z]{2}$")


def clean(text):
    """One line of plain text: no tabs, newlines or control characters."""
    return " ".join("".join(ch for ch in word if ch.isprintable()) for word in text.split()).strip()


def build(rows):
    best = {}
    for row in rows:
        code = (row.get("iata_code") or "").strip()
        kind = row.get("type", "")
        if not IATA.match(code) or kind not in RANK:
            continue
        if kind == "small_airport" and row.get("scheduled_service") != "yes":
            continue
        country = (row.get("iso_country") or "").strip()
        try:
            lat, lon = float(row["latitude_deg"]), float(row["longitude_deg"])
        except (KeyError, TypeError, ValueError):
            continue
        if not COUNTRY.match(country) or not (-90 <= lat <= 90) or not (-180 <= lon <= 180):
            continue
        rank = (RANK[kind], row.get("scheduled_service") == "yes")
        if code in best and best[code][0] >= rank:
            continue
        city = clean(row.get("municipality") or "") or clean(row.get("name") or "")
        best[code] = (rank, f"{code}\t{lat:.4f}\t{lon:.4f}\t{country}\t{city}")
    return [best[c][1] for c in sorted(best)]


def main(argv):
    if len(argv) not in (2, 3):
        sys.stderr.write(__doc__)
        return 2
    with open(argv[1], newline="", encoding="utf-8") as f:
        lines = build(csv.DictReader(f))
    out = "\n".join(lines) + "\n"
    if len(argv) == 3:
        with open(argv[2], "w", encoding="utf-8") as f:
            f.write(out)
    else:
        sys.stdout.write(out)
    sys.stderr.write(f"{len(lines)} airports\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
