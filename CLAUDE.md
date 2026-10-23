# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

Rat is a macOS network monitor and reactive application firewall modelled on Little Snitch. It has no Network Extension entitlement (no paid developer account), so it cannot intercept connections before they start; see `docs/ARCHITECTURE.md` sections 7-8.

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
- Offline geo: `GeoService` reads `Contents/Resources/Vendor/dbip-city-lite.mmdb` (or `RAT_GEOIP_DB`); the Mac's own position comes from the time zone (`/usr/share/zoneinfo/zone.tab`).
- All user data lives in `~/Library/Application Support/com.imanmontajabi.Rat`. `~/Library/Application Support/Rat` belongs to something else; do not touch it.
- `screenshot/` (git-ignored) holds the raw Little Snitch reference screenshots; `SnapshotTests` read them when present.
