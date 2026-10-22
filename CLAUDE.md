# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

Rat is a macOS per-app outbound firewall prototype modelled on Little Snitch (design derived from REA static analysis of its network extension; see README).

## Commands

All code lives in the Swift package at `RatFilter/`:

```sh
cd RatFilter
swift build
swift test
swift test --filter RuleEngineTests/testSpecificBeatsGeneral   # single test
```

## Architecture

- `RatFilterCore` is pure Swift with no system dependencies: rule model, specificity-based matching (most specific wins, deny wins ties, disabled/unapproved rules ignored), `RuleEngine`, JSON `RuleStore`.
- `RatFilterExtension` holds `RatFilterProvider`, an `NEFilterDataProvider` that maps flows to `Connection` values (signing info via `SecCode` from the flow audit token, because `sourceAppIdentifier` is unavailable on macOS), evaluates them, and for `.ask` pauses the flow and resumes it from the `askUser` callback.
- The provider compiles but cannot run from SwiftPM: it needs a signed system extension with the Network Extension content-filter entitlement inside a host app, which doesn't exist yet.

`screenshot/` (gitignored) holds raw reference screenshots; optimized copies are in `docs/screenshots/`.
