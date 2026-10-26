#!/bin/sh
# Builds the Release Rat.app for Apple Silicon (ad-hoc signed), stamped with the version from the root Version
# file. Used by the nightly and release workflows and for local release builds.
#
#   scripts/build-release.sh <out-dir> [build-number]
#
# Leaves <out-dir>/Rat.app. The build number (CFBundleVersion) defaults to 1; CI passes its run number.
set -eu
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${1:?usage: $0 <out-dir> [build-number]}"
BUILD="${2:-1}"
VERSION="$("$ROOT/scripts/version.sh" get)"
DERIVED="${RAT_DERIVED_DATA:-$ROOT/.build/release-dd}"

cd "$ROOT"
"$ROOT/scripts/version.sh" check >/dev/null
"$ROOT/scripts/fetch-geoip.sh"
xcodegen generate --quiet
xcodebuild -project Rat.xcodeproj -scheme Rat -configuration Release -derivedDataPath "$DERIVED" \
  -destination 'generic/platform=macOS' ARCHS=arm64 ONLY_ACTIVE_ARCH=NO \
  MARKETING_VERSION="$VERSION" CURRENT_PROJECT_VERSION="$BUILD" \
  build -quiet

APP="$DERIVED/Build/Products/Release/Rat.app"
mkdir -p "$OUT"
rm -rf "$OUT/Rat.app"
ditto "$APP" "$OUT/Rat.app"
codesign --verify --deep --strict "$OUT/Rat.app"
for f in Contents/MacOS/Rat Contents/MacOS/rat-enforcerd Contents/Resources/Vendor/dbip-city-lite.mmdb Contents/Resources/Vendor/dbip-asn-lite.mmdb; do
  [ -e "$OUT/Rat.app/$f" ] || { echo "missing $f in Rat.app" >&2; exit 1; }
done
lipo -archs "$OUT/Rat.app/Contents/MacOS/Rat" | grep -qx arm64 || { echo "Rat is not arm64-only" >&2; exit 1; }
echo "built $OUT/Rat.app $(defaults read "$OUT/Rat.app/Contents/Info.plist" CFBundleShortVersionString) ($BUILD)"
