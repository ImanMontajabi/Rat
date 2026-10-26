#!/bin/sh
# Runs the UI test suite (RatUITests) and the snapshot goldens, the visual checks CI cannot do: both need a
# logged-in GUI session, and the goldens were recorded on this kind of display. The UI tests drive a demo build
# (RAT_DEMO_MAP=1, bundle id com.imanmontajabi.Rat.uitest): your running Rat, its rules, deny list and
# preferences are never touched. The first run asks to allow UI automation (an administrator prompt).
# Keep your hands off the keyboard and mouse while it runs: the tests type into the app in front. A non-Latin
# keyboard layout is switched to U.S. (or ABC) for the run and restored afterwards.
#
#   scripts/test-ui.sh                                         everything
#   scripts/test-ui.sh -only-testing:RatUITests/RatUITests/testSettingsOpensEveryTab   one test
set -eu
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DERIVED="${RAT_DERIVED_DATA:-$ROOT/.build/uitest-dd}"
cd "$ROOT"
xcodegen generate --quiet

# XCUITest types through the current keyboard layout.
mkdir -p "$DERIVED"
swiftc -O -o "$DERIVED/input-source" "$ROOT/scripts/input-source.swift"
PREVIOUS="$("$DERIVED/input-source" latin)"
trap '"$DERIVED/input-source" select "$PREVIOUS" || true' EXIT
trap 'exit 130' INT TERM

status=0
xcodebuild -project Rat.xcodeproj -scheme RatUITests -destination 'platform=macOS,arch=arm64' -derivedDataPath "$DERIVED" \
  -resultBundlePath "$DERIVED/RatUITests-$(date +%Y%m%d-%H%M%S).xcresult" test "$@" || status=$?
if [ $# -eq 0 ]; then
  xcodebuild -project Rat.xcodeproj -scheme Rat -destination 'platform=macOS,arch=arm64' -derivedDataPath "$DERIVED" \
    test -only-testing:RatTests/SnapshotTests || status=$?
fi
[ "$status" -eq 0 ] && echo "UI tests and snapshot goldens passed" || echo "UI tests failed (results in $DERIVED)" >&2
exit "$status"
