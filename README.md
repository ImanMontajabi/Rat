<p align="center"><img src="docs/icon.png" width="120" alt="Rat"></p>

# Rat

A per-application outbound firewall for macOS, modelled on how Little Snitch works.
Rat intercepts each new network connection, matches it against rules, and either
allows it, blocks it, or pauses it so you can decide.

> **Status: v0.2.0.** A network monitor with reactive blocking. It is **not** a per-process
> firewall like Little Snitch: that needs Apple's Network Extension entitlement (paid developer
> program). See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md), section 7.

## What works today

- Live list of apps and their connections, per-app traffic sparklines, session totals and a traffic chart (5m / 1h / 1d / 1w, history kept for a week).
- Inspector with path, code-signing ID, server addresses and locations.
- Map of server locations. **Off by default**: enabling it sends server IPs to ipwho.is.
- Deny / Allow per app. Deny collects the server addresses the app talks to and, when you click *Apply blocking*, loads them into the macOS `pf` firewall (one admin-password prompt per apply, nothing installed permanently). **Limits:** a blocked address is blocked for every app, and new addresses are only blocked after the next Apply.
- Check for Updates (Rat menu) against GitHub Releases.

## Install

Download the `.dmg` from Releases and drag Rat to Applications. The app is ad-hoc signed, not notarized, so the first launch needs right-click, Open (or `xattr -dr com.apple.quarantine /Applications/Rat.app`).

## Where the design comes from

The original design comes from static reverse engineering of the Little Snitch network extension
(with [REA](https://github.com/morluto/rea)), not from its source. Observed in the binary:

- A `NEFilterDataProvider` content filter sees every new flow in `handleNewFlow`.
- The verdict is allow, drop, or pause. A paused flow is resumed later with
  `resumeFlow:withVerdict:` once the user answers.
- Rules are re-applied to all live flows whenever the rule set changes.
- Rules match on code signature / team ID, not just file path.
- Imported or auto-created rules can be marked *unapproved* until reviewed.

The v0.1 prototype reproduced this flow (kept in `RatFilter/Sources/RatFilterExtension`, not used by the app because it cannot run without the entitlement):

```
NEFilterDataProvider.handleNewFlow
        │  process identity from audit token (signing ID, team ID, path)
        ▼
   RuleEngine.evaluate ── allow ──▶ .allow()
        │                └─ deny ──▶ .drop()
        └─ ask ──▶ .pause() ──▶ UI prompt ──▶ new rule ──▶ resumeFlow
```

## Layout

| Path | Contents |
|---|---|
| `RatFilter/Sources/RatFilterCore` | `Rule`, `Connection`, `RuleEngine`, JSON `RuleStore`. No system dependencies. |
| `RatFilter/Sources/RatFilterExtension` | `RatFilterProvider`, the `NEFilterDataProvider` subclass (dormant). |
| `RatFilter/Sources/RatMonitor` | `libproc` connection sampler and `nettop` traffic sampler. |
| `App/` | SwiftUI app: monitor window, ledger, pf blocking, update check. |
| `RatFilter/Tests` | Rule engine tests. |

## Rule semantics

- A rule can match signing ID or team ID, remote domain (including subdomains), remote
  address, port range and protocol.
- The most specific matching rule wins. At equal specificity, deny beats allow.
- Disabled and unapproved rules never match.
- With no matching rule the default verdict applies (`ask`).

## Build and test

```sh
cd RatFilter && swift test          # packages
cd .. && xcodegen generate
xcodebuild -scheme Rat -configuration Release -destination 'platform=macOS' build
xcodebuild -scheme Rat test
```

## What's missing

- True per-process blocking and pre-connection prompts (needs the Network Extension entitlement).
- Per-app history older than one launch for connections and domains; blocking only by server address.
- DNS encryption, blocklists, profiles.

## Reference screenshots

Screenshots of Little Snitch used as UI reference. They are of a third-party product and
show what Rat is aiming for, not Rat itself.

| | |
|---|---|
| ![Network monitor](docs/screenshots/network-monitor-map.jpg) | ![Process inspector](docs/screenshots/process-inspector.jpg) |
| ![Profile switching](docs/screenshots/profile-switching.png) | ![Unapproved rules](docs/screenshots/unapproved-rules.png) |
