<p align="center"><img src="docs/icon.png" width="120" alt="Rat"></p>

# Rat

A per-application outbound firewall for macOS, modelled on how Little Snitch works.
Rat intercepts each new network connection, matches it against rules, and either
allows it, blocks it, or pauses it so you can decide.

> **Status: early prototype (v0.1.0).** The rule engine is implemented and tested. The
> system-extension host app, prompt UI and network monitor are not built yet.

## How it works

This design comes from static reverse engineering of the Little Snitch network extension
(with [REA](https://github.com/morluto/rea)), not from its source. Observed in the binary:

- A `NEFilterDataProvider` content filter sees every new flow in `handleNewFlow`.
- The verdict is allow, drop, or pause. A paused flow is resumed later with
  `resumeFlow:withVerdict:` once the user answers.
- Rules are re-applied to all live flows whenever the rule set changes.
- Rules match on code signature / team ID, not just file path.
- Imported or auto-created rules can be marked *unapproved* until reviewed.

Rat reproduces this flow:

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
| `RatFilter/Sources/RatFilterExtension` | `RatFilterProvider`, the `NEFilterDataProvider` subclass. |
| `RatFilter/Tests` | Rule engine tests. |

## Rule semantics

- A rule can match signing ID or team ID, remote domain (including subdomains), remote
  address, port range and protocol.
- The most specific matching rule wins. At equal specificity, deny beats allow.
- Disabled and unapproved rules never match.
- With no matching rule the default verdict applies (`ask`).

## Build and test

```sh
cd RatFilter
swift build
swift test
```

## What's missing

- **Host app and system extension packaging.** Content filters only run inside a signed
  system extension with the
  `com.apple.developer.networking.networkextension` = `content-filter-provider-systemextension`
  entitlement, which Apple must grant to your developer team.
- Connection prompt UI and the XPC channel between it and the extension.
- Re-evaluating already-paused flows when rules change.
- Network monitor (per-process traffic, domains, map).

## Reference screenshots

Screenshots of Little Snitch used as UI reference. They are of a third-party product and
show what Rat is aiming for, not Rat itself.

| | |
|---|---|
| ![Network monitor](docs/screenshots/network-monitor-map.jpg) | ![Process inspector](docs/screenshots/process-inspector.jpg) |
| ![Profile switching](docs/screenshots/profile-switching.png) | ![Unapproved rules](docs/screenshots/unapproved-rules.png) |
