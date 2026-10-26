# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

Rat is a macOS network monitor and reactive application firewall modelled on Little Snitch. It has no Network Extension entitlement (no paid developer account), so it cannot intercept connections before they start; see `docs/ARCHITECTURE.md` sections 7-8.

## Workflow (mandatory)

GitHub rulesets protect `main` and `release`: no direct pushes, no force pushes, no deletion. Every change goes through a pull request.

- **Branches:** `main` is integration, `release` is the stable line. Work on `feat/<name>`, `fix/<name>`, `ci/<name>` or `test/<name>`, branched from an up-to-date `main`; one logical change per branch. Never commit on `main` or `release`.
- **Changelog fragment:** every branch adds `changelog.d/<slug>.<type>.md` (types: added, changed, fixed, removed, security, internal; see `changelog.d/README.md`). `scripts/changelog.py new <type> <slug> "…"` creates one; `scripts/changelog.py check --base origin/main` is what CI runs. Only a PR that changes nothing for anyone may use the `skip-changelog` label instead.
- **Version:** the root `Version` file (`X.Y.Z`, no extension) is the single source of truth and holds the version being developed on `main`. `scripts/version.sh set X.Y.Z` writes it and `project.yml`'s `MARKETING_VERSION`; `scripts/version.sh check` fails when they differ.
- **Pull request:** push the branch and open it with `gh pr create --base main` (fill in `.github/pull_request_template.md`: summary, architecture, checklist). Merge only when CI is green. Commits and PR bodies keep the attribution lines.
- **Releases:** a merge into `main` publishes a nightly pre-release. A stable release is a PR from `main` into `release`: the release workflow publishes `v<Version>` when `Version` is higher than the last stable tag, then opens a PR back to `main` that compiles the fragments into `CHANGELOG.md` and bumps `Version` to the next minor. Merging into `release` publishes a release: only the maintainer does it.
- **CI (`.github/workflows/`):** `ci.yml` runs on every PR: the fragment and Version checks (Ubuntu), `swift test` and `xcodebuild -scheme Rat test` (macOS), and a Release build packed into a DMG that is attached to the run. `nightly.yml` (push to `main`) publishes `v<Version>-nightly.<YYYYMMDD>.<sha>` as a pre-release with the DMG, `.sha256` and the notes rendered from the fragments, keeping the newest five. `release.yml` (push to `release`) does the stable release described above. All builds share `.github/actions/setup-macos` (newest stable Xcode, XcodeGen, create-dmg, DB-IP cached per month), `scripts/build-release.sh <out> [build]` and `scripts/make-dmg.sh <Rat.app> <out.dmg>`; run the two scripts locally for the same build. Actions are pinned to commit SHAs.

## Commands

```sh
./scripts/fetch-geoip.sh                       # one-time: DB-IP database into App/Vendor (git-ignored, ~125 MB)
xcodegen generate                              # Rat.xcodeproj is generated from project.yml, never committed
xcodebuild -project Rat.xcodeproj -scheme Rat -configuration Debug build
xcodebuild -project Rat.xcodeproj -scheme Rat test
xcodebuild -scheme Rat test -only-testing:RatTests/RulesModelTests/testAlertScopes   # single test
TEST_RUNNER_RAT_RECORD_SNAPSHOTS=1 xcodebuild -scheme Rat test -only-testing:RatTests/SnapshotTests   # re-record goldens
(cd RatFilter && RAT_GEOIP_DB=../App/Vendor/dbip-city-lite.mmdb swift test)   # packages; --filter Name for one
RAT_DEMO_MAP=1 RAT_OPEN=settings|rules RAT_SETTINGS_TAB=APS open Rat.app   # Debug only: fixed demo data (never touches real data), open a window/tab at launch
scripts/version.sh check                       # Version and project.yml agree
scripts/changelog.py render                    # preview the unreleased notes from changelog.d/
scripts/build-release.sh /tmp/out && scripts/make-dmg.sh /tmp/out/Rat.app /tmp/out/Rat.dmg   # the CI release build
```

## Architecture

- `RatFilter/` is a Swift package: `RatFilterCore` (pure rule engine: `Rule`, `RuleSet` with profiles/groups/triggers, `RuleEngine`, import/export), `RatMonitor` (libproc `ConnectionSampler`, `nettop` `TrafficSampler`, `SystemSnapshot` parser for the root helper's lsof output), `RatGeo` (own `.mmdb` reader), `RatFilterExtension` (dormant `NEFilterDataProvider`).
- `App/Model/Ledger.swift` is the hub: samples every 1.5 s, groups processes into apps (`AppIdentity` = outermost `.app`), evaluates each remote against `RulesModel.engine`, raises alerts for `.ask`, hands the helper the denied apps and the local ports of rule-denied sockets (`refreshEnforcement`).
- UI: `SidebarView` (monitor left pane, toolbar rows start below the traffic lights), `RulesWindow` (sidebar + table, Little Snitch layout), `SettingsWindow` (⌘,, `Settings` scene; tab names follow Little Snitch's `Settings.strings`). Preferences live in `AppSettings` (UserDefaults).
- New installs default to Silent Allow (`RuleSet.version` 2; version 1 files migrate). Alerts are re-validated every tick (`AlertCenter.revalidate`) so an app with a rule never prompts.
- Chart: `Ledger.chartLayout` tiles the window with bars and shrinks it to the data that exists.
- `RulesModel` wraps the engine for the UI (policy buttons are a whole-app rule; alerts create scoped rules). `approved` is a review marker only: `enabled` gates matching, imported rules arrive disabled+unapproved.
- `RatFilter/Sources/RatEnforce` + `Enforcerd/main.swift` build `rat-enforcerd`, the root daemon (KeepAlive LaunchDaemon `com.imanmontajabi.rat.pf`): it reads `denied-apps.txt` (written by `Ledger.deniedAppPaths`) and `denied-ports.txt` and keeps the pf anchor in step by blocking the local ports of every socket of denied apps. **Rat never blocks remote addresses** (no table, no `pass` rules, no `pfctl -k`): an address is shared by every app, DNS included. `ProcessGrouping` (RatMonitor) decides which app a process belongs to for both the app and the daemon. `scripts/verify-blocking.sh` is the live test (needs sudo); `scripts/rat-status.sh` shows what is enforced (the daemon's status file `/var/run/com.imanmontajabi.rat.enforcer.json`). A process-list Deny wins over the app's narrower allow rules. The daemon also blocks a denied app's loopback TCP connections to other programs on lo0 (local proxies, `ssh -L`).
- Proxy unmasking (1.1.0): `ProxyWatch` (RatEnforce) reads proxy requests on lo0 through BPF (`LoopbackFilter`, `ProxyHandshake`) and publishes the user's proxied flows in `/var/run/com.imanmontajabi.rat.proxied.json` (0600, `--owner-uid`); `ProxyUnmasking` (app) merges them, with a `KERN_PROCARGS2` fallback (`ProcessArguments`), into `RemoteHost.via`. `scripts/test-proxy.py` is the local test proxy for `verify-blocking.sh` phase 3.
- `Enforcer` writes `denied-apps.txt` / `denied-ports.txt` and installs the two opt-in root LaunchDaemons (`rat-enforcerd`, and `App/Resources/rat-pf-helper.sh snapshot`). Never run the install paths in tests.
- Preferences go through `Preferences.store` (a separate suite under XCTest): tests must never write the user's real defaults.
- Offline geo: `GeoService` reads `Contents/Resources/Vendor/dbip-city-lite.mmdb` and `dbip-asn-lite.mmdb` (or `RAT_GEOIP_DB` / `RAT_GEOIP_ASN_DB`), or the user's files from Settings > GeoIP (`GeoDatabases`, copied into `GeoIP/` in the data folder, validated, never overwritten while mapped). The MMDB reader treats files as untrusted (bounds checks, decode budget). The Mac's own position comes from the time zone (`/usr/share/zoneinfo/zone.tab`).
- Connection details (1.2.0): `PortNames` (usual service per port), `RemoteHost.pid/process` ("via <helper>"; the macOS row is grouped by service, `SharedServices` marks services that work for other apps, and the macOS row has no one-click Deny), `RemoteHost.network` (ASN), `RemoteHost.route` from `RouteMarker`/`NetworkRoutes` (socket on a tunnel interface → VPN, named via the tunnel's kernel-control owner, also published by the helper as `tunnels`; system proxies from `SCDynamicStoreCopyProxies`).
- All user data lives in `~/Library/Application Support/com.imanmontajabi.Rat`. `~/Library/Application Support/Rat` belongs to something else; do not touch it.
- `screenshot/` (git-ignored) holds the raw Little Snitch reference screenshots; `SnapshotTests` read them when present.
