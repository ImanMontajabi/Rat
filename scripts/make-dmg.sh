#!/bin/sh
# Packs Rat.app into a styled disk image (background, icon layout, Applications link) and writes its SHA-256
# next to it. Uses create-dmg (brew install create-dmg) and falls back to a plain image when Finder cannot be
# scripted (a CI runner without a GUI session).
#
#   scripts/make-dmg.sh <path/to/Rat.app> <out.dmg>
#
# Leaves <out.dmg> and <out.dmg>.sha256 ("<hash>  <file name>", checkable with shasum -c).
set -eu
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
APP="${1:?usage: $0 <Rat.app> <out.dmg>}"
DMG="${2:?usage: $0 <Rat.app> <out.dmg>}"
STAGE="$(mktemp -d "${TMPDIR:-/tmp}/rat-dmg.XXXXXX")"
trap 'rm -rf "$STAGE"' EXIT

ditto "$APP" "$STAGE/Rat.app"
rm -f "$DMG"
styled=no
if command -v create-dmg >/dev/null 2>&1; then
  # create-dmg exits 2 when only the cosmetic Finder step failed; the image is then discarded and rebuilt plain.
  if create-dmg --volname Rat --volicon "$STAGE/Rat.app/Contents/Resources/AppIcon.icns" \
       --background "$ROOT/assets/dmg-background.tiff" --window-pos 200 120 --window-size 640 400 \
       --icon-size 112 --text-size 13 --icon Rat.app 160 170 --hide-extension Rat.app --app-drop-link 480 170 \
       --hdiutil-quiet --no-internet-enable "$DMG" "$STAGE" >/dev/null 2>"$STAGE.log"; then
    styled=yes
  else
    echo "create-dmg failed, building a plain image:" >&2; tail -5 "$STAGE.log" >&2 || true
    rm -f "$DMG"
  fi
  rm -f "$STAGE.log"
fi
if [ "$styled" = no ]; then
  ln -s /Applications "$STAGE/Applications"
  hdiutil create -volname Rat -srcfolder "$STAGE" -ov -format UDZO -quiet "$DMG"
fi
hdiutil verify -quiet "$DMG"
(cd "$(dirname "$DMG")" && shasum -a 256 "$(basename "$DMG")" > "$(basename "$DMG").sha256")
echo "$DMG ($( [ "$styled" = yes ] && echo styled || echo plain )): $(cut -d' ' -f1 "$DMG.sha256")"
