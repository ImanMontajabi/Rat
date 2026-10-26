# Changelog

User-facing changes in each Rat release. Unreleased changes live as fragments in [`changelog.d/`](changelog.d/README.md)
until a release compiles them here; nightly pre-releases show them as a preview. Full notes, with test results and
DMG checksums, are on the [Releases](https://github.com/ImanMontajabi/Rat/releases) page.

<!-- releases -->

## [1.2.0] - 2026-10-23

### Added

- Port names: each connection shows the service usually on its port (`TCP 443 · HTTPS`, `UDP 443 · QUIC`) in the inspector, the list and alerts (#1).
- The inspector shows which process holds each connection ("via Google Chrome Helper (pid 812)"); the macOS row is grouped by service and marks services that work for other apps (#5).
- Network owner of each server (`AS13335 Cloudflare, Inc.`) from the bundled offline DB-IP ASN Lite database, and *Top Networks* in the Summary (#4).
- Settings > GeoIP: choose your own City or ASN `.mmdb`, or download the latest DB-IP Lite file (#3).
- Connections through a VPN tunnel or a system proxy are marked "via VPN (…)" / "via System … Proxy (…)" (#2).

### Changed

- The macOS row has no one-click Deny: denying all system services would cut DNS for every app.

### Security

- The MMDB reader treats database files as untrusted (bounds checks, decode budget).

## [1.1.0] - 2026-10-23

### Added

- Destinations behind local proxies and SSH tunnels (HTTP CONNECT, absolute-URI HTTP, SOCKS5, SOCKS4/4a) are unmasked from the proxy request on lo0, or from the client's command line without the helper.
- The map draws This Mac → proxy server → destination.

### Security

- A denied app's loopback connections to other programs (local proxies, `ssh -L`) are cut on lo0.

## [1.0.5] - 2026-10-23

### Fixed

- Deny from the process list blocks again in the app: a test no longer writes the real preferences, and a Deny wins over the app's narrower allow rules.

### Added

- The firewall helper publishes its status, shown in Settings > Security, the inspector and the list footer.

## [1.0.4] - 2026-10-23

### Security

- Rat never blocks server addresses: the pf anchor holds only stateless rules for the local ports of denied sockets.

## [1.0.3] - 2026-10-23

### Fixed

- Denied apps are cut by their own local ports only, without collateral blocking of shared servers.

## [1.0.2] - 2026-10-23

### Added

- The root enforcer `rat-enforcerd`; helpers group with their app (Chrome, Steam, Safari's WebKit networking).

## [1.0.1] - 2026-10-22

### Changed

- Settings and Rules windows rebuilt after Little Snitch's layout; Silent Allow is the default mode.

## [1.0.0] - 2026-10-22

### Added

- Rules engine with profiles and rule groups, connection alerts, menu bar item, offline map and the optional root helper.

## [0.2.0] - 2026-10-22

### Added

- Network monitor: per-app connections, traffic chart, map and inspector.

## [0.1.0] - 2026-10-22

### Added

- First prototype: rule model and engine.
