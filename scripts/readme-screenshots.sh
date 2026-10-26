#!/bin/sh
# Retakes the README's screenshots (docs/screenshots/{monitor-hierarchy-tags,rules-window,settings-window}.png)
# from the demo data with UITests/ReadmeScreenshots: nothing of this Mac's connections, rules or settings is shown.
# Like scripts/test-ui.sh it needs a logged-in GUI session; keep hands off the keyboard and mouse while it runs.
set -eu
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DERIVED="${RAT_DERIVED_DATA:-$ROOT/.build/uitest-dd}"
OUT="${1:-$ROOT/docs/screenshots}"
cd "$ROOT"
xcodegen generate --quiet
mkdir -p "$DERIVED"
swiftc -O -o "$DERIVED/input-source" "$ROOT/scripts/input-source.swift"
PREVIOUS="$("$DERIVED/input-source" latin)"
RESULT="$DERIVED/ReadmeScreenshots-$(date +%Y%m%d-%H%M%S).xcresult"
EXPORT="$(mktemp -d "${TMPDIR:-/tmp}/rat-shots.XXXXXX")"
trap '"$DERIVED/input-source" select "$PREVIOUS" || true; rm -rf "$EXPORT"' EXIT
trap 'exit 130' INT TERM

TEST_RUNNER_RAT_SCREENSHOTS=1 xcodebuild -project Rat.xcodeproj -scheme RatUITests -destination 'platform=macOS,arch=arm64' \
  -derivedDataPath "$DERIVED" -resultBundlePath "$RESULT" test -only-testing:RatUITests/ReadmeScreenshots
xcrun xcresulttool export attachments --path "$RESULT" --output-path "$EXPORT"
# manifest.json maps each exported file to the attachment's name (the file name it gets in docs/screenshots).
/usr/bin/python3 - "$EXPORT" "$OUT" <<'PY'
import json, os, shutil, sys
src, out = sys.argv[1], sys.argv[2]
os.makedirs(out, exist_ok=True)
for test in json.load(open(os.path.join(src, "manifest.json"))):
    for a in test.get("attachments", []):
        name = a.get("suggestedHumanReadableName", "")
        wanted = next((n for n in ("monitor-hierarchy-tags.png", "rules-window.png", "settings-window.png") if name.startswith(n[:-4])), None)
        if wanted:
            shutil.copyfile(os.path.join(src, a["exportedFileName"]), os.path.join(out, wanted))
            print("saved", os.path.join(out, wanted))
PY
