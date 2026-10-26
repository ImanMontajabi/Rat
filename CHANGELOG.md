# Changelog

User-facing changes in each Rat release. Unreleased changes live as fragments in [`changelog.d/`](changelog.d/README.md)
until a release compiles them here; nightly pre-releases show them as a preview. Full notes, with test results and
DMG checksums, are on the [Releases](https://github.com/ImanMontajabi/Rat/releases) page.

<!-- releases -->

## [1.3.0] - 2026-10-26

### Added

- The map shows only what the list shows: the search, the VPN and proxy filter (chip or the words vpn / proxy), and the other filters narrow its lines and pins too; searching a city draws only the lines to it.
- Apps expand into a tree: the main process's connections first, then each helper or XPC service (and each macOS service) with its PIDs, traffic and own connections. Every connection shows the bytes of its open sockets, command-line tools show the app that started them, and selecting an app, a process or one connection scopes the map and the inspector.
- Connections through a VPN or a proxy carry a tag in the list and the inspector: `VPN · Windscribe · utun3`, `Proxy · ssh`, `Proxy · System HTTPS`. Loopback connections to a local proxy program (ssh, Tor, Clash, V2Ray, mitmproxy, …) are tagged even without the firewall helper. Type `vpn` or `proxy` in the search field, or use the new route filter, to see only those connections.

### Changed

- The Summary in the inspector counts what the search and filters leave (apps, domains, countries, networks, traffic, denied and unconfirmed connections) and says when it is filtered.

### Fixed

- A connection through a plain forwarding proxy (one that connects to the destination itself) no longer shows the destination as the proxy's server on the map; connections through a local proxy on [::1] name the right listener.
- A slow or unreachable DNS server no longer stalls the Network Monitor: host names are looked up in the background (at most four at a time) and loopback, unspecified and link-local addresses are never looked up. A connection whose name is still pending is judged by the rules a moment later (at most 3 seconds), so domain rules still match.
- Fixed three bugs the UI tests found: Allow/Deny and the Rules window took up to a sampling pass (1.5 s) to show a change, the active profile's checkmark in the Rules sidebar did not move when another profile was activated, and the Advanced tab of Settings was hidden in the toolbar's overflow menu.
- App and process rows show the VPN and proxy tags of their connections (each tag once; when the row is narrow they fold into a count, then into symbols). A connection without an address of its own is tagged VPN when the routing table sends it through the tunnel, and the VPN client's own connection to its server is tagged "VPN server" instead of VPN.

### Development

- Demo mode (Debug builds with `RAT_DEMO_MAP`, used by screenshots and the UI tests) uses its own preferences, sees no firewall helper, cannot install or remove it, and skips the update check.
- CI checks a PR's changelog fragment against the base commit of the event, so retargeting a stacked PR no longer fails the check.
- Live proxy tests: real curl through a loopback SOCKS5 and HTTP CONNECT proxy (IPv4 and IPv6) must show the real destination with its Proxy tag, from the command line and, where the firewall helper is installed, from its lo0 capture.
- GitHub Actions check every pull request, publish a nightly pre-release for every merge into `main` and the stable release from the `release` branch, each with a styled DMG and its SHA-256.
- A UI test suite (`RatUITests`, run with `scripts/test-ui.sh`) clicks through the process tree, VPN and proxy tags, search and route filters, Allow/Deny, the Rules window, profiles and every Settings tab on demo data, under its own bundle identifier so the running Rat is never touched.
- scripts/test-ui.sh switches a non-Latin keyboard layout to U.S. or ABC for the run and restores it, and the UI tests ignore saved window state, so a window minimized in an earlier run no longer breaks every test.
- The version lives in the root `Version` file, and every change carries a changelog fragment in `changelog.d/` that releases compile into `CHANGELOG.md`.

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
