# Changelog

User-facing changes in each Rat release. Unreleased changes live as fragments in [`changelog.d/`](changelog.d/README.md)
until a release compiles them here; nightly pre-releases show them as a preview. Full notes, with test results and
DMG checksums, are on the [Releases](https://github.com/ImanMontajabi/Rat/releases) page.

<!-- releases -->

## [1.6.0] - 2026-10-31

### Added

- Rules can name the servers in one country (picked with its flag in the Rules window, or started from a connection's inspector or a country group): the helper looks servers up in the same offline database as the map and cuts only the matching sockets by their local ports.
- Only through a VPN can name the VPN's country (Only through a VPN in 🇩🇪 Germany): Rat and the helper find each tunnel's server offline from the VPN app's own connection (for WireGuard, the route it keeps to its server) and cut the app's connections through a tunnel that leads elsewhere.
- **Only through a VPN** (#45): a switch in the inspector for an app or one of its processes, and a condition in the Rules window. Every connection the app makes outside a VPN tunnel is cut by the helper within milliseconds, whatever ✓ it has; Rat cuts after a connection opens, so its first packets can still leave (update the helper in Settings > Security for the fast cut).

### Changed

- The inspector's Rules section no longer repeats the ✗/✓ of the selected app, process or connection: set them on its row in the list, and the inspector lists the rules that result.
- Local connections have a labeled Local switch beside the search field: turn it off to hide this Mac's own, LAN and Bonjour traffic in the list, the map and the Summary. It replaces the small house icon inside the search field, and keeps its setting.
- Traffic on the map is drawn as laser tracers: a glowing beam with a fading tail races along each line (purple out from this Mac, blue in from the server) and a ring ripples out where it lands.

### Fixed

- With nothing blocked, the helper checks pf every 10 s instead of every 2 s (a fifth of the `pfctl` runs) and sleeps a second between passes. A new block is enforced as fast as before: the helper loads its ports first and checks pf on the next pass.
- The map's moving traffic stays on its lines and inside the map: after the window took its saved size at launch, or the inspector was shown or hidden, pulses ran beside their lines and some were drawn over the app list.

### Development

- The helper deletes 1.0.3's leftover address list before its first pf check, so `verify-blocking.sh`'s start-up check no longer fails on a cold start; phase 5 skips the cut outside the tunnel when something else (a VPN's kill switch) already blocks it.

## [1.5.0] - 2026-10-28

### Added

- Connections a peer started (to a port this Mac listens on) are rows of their own, tagged ↓ Incoming, without ✗/✓ and never asked about in Alert Mode; long-lived connections that mostly receive (a download, a server push, a media stream) are tagged ↓ stream.
- The helper now applies rules for one process of an app and for one connection itself, every few milliseconds, as it does for an app denied as a whole: such a connection is cut while it is being opened instead of after Rat's next pass, when it is already open. Rat hands the helper its rules and the names it found for servers in `deny-rules.json`; only the local ports of matching sockets are blocked, never a server's address. Update Helper in Settings > Security to use it.
- Places show their country's flag (connection rows and their tooltips, the inspector, Top Countries, map labels), and a Hide Local chip, remembered between launches, leaves out loopback, LAN, link-local, Bonjour and mDNS connections and the apps and processes that have only those, in the list, the map and the Summary.
- The map shows traffic moving: purple pulses run out from This Mac for what it sends, blue ones run in for what it receives, both on a two-way line, at 24–30 frames a second and only while the window is seen and something moves (Reduce Motion stops them).
- Rules can be for one process of an app (a helper, an updater, the WebKit process working for Safari) and for one connection of a process (its server, port and protocol). The process list's Deny and Allow decide the narrowest first: a connection's, then a process's, then the app's, over the app's rules from alerts.
- The process list has ✗/✓ for each process and each connection (a TCP and a UDP connection to one server are separate rows), showing what a row follows from its process or app; the inspector lists the rules about the selected app, process or connection and sets its ✗/✓; Manage Rules… opens the Rules window on that row (new Apps / Processes section) and New Rule starts from it.

### Fixed

- Rows in the list keep their numbers whole: a connection's port and size and a process's connection count and size are never cut or wrapped ("TCP…", "1,7…", "430 / bytes"). With little room the tags shrink to their symbols, the port drops its service name and a process drops its pid, and only then is a long name cut in the middle. The macOS inspector writes pids without a thousands separator ("pid 2086", not "pid 2.086").
- A ✗ on a process or connection of Safari or another program macOS loads from a cryptex (WebKit's networking process, Safari's helpers) now blocks it: Rat took some paths from `ps` and the helper from the kernel, which name those programs differently, so the rule never matched. Rat now names every process by the kernel's path and both compare paths in one spelling; rules saved before still match. A ✗ or ✓ in the list now takes effect at once instead of on the next 1.5 s pass.
- A deny made while nothing else was denied takes effect at once: the helper now wakes as soon as Rat hands it the change, instead of up to a quarter of a second later, so a download already under way is cut before more of it arrives.
- When an app opens several connections to the same server and port, a rule that denies them now cuts all of them, not only the first.
- The helper no longer stops enforcing rules after running for a while: every pfctl run left a file open until it hit the system's limit, after which pf could not be checked, repaired or updated.
- The helper uses much less CPU while a ✗ is set on one process or connection (14.5 % → 3.6 % with a ✗ on Safari's SearchHelper): it reads only the processes the rule can match, not every process of the app, and lists the Mac's processes only when one has started. While a denied program is not running, the helper now checks for it every 20 ms instead of every 0.25 s.
- The map no longer redraws on every pass when only traffic numbers change, address caches stay bounded on a Mac that stays up, and the helper no longer keeps a core busy for two seconds when it starts or when an app is denied or allowed.
- A rule for one system service in the macOS row (for example /usr/sbin/mDNSResponder or /usr/bin/curl), or for one helper's path, now matches that service; before, only the app's path was compared and such rules never applied.

### Development

- A weekly security audit (Mondays, on demand, and on PRs that change dependencies or workflows) checks the pinned GitHub Actions against the GitHub Advisory Database and package lockfiles with osv-scanner, and opens a security issue when something is found. CLAUDE.md now requires tests, UI tests, live verification and a CPU and memory measurement (scripts/measure-resources.sh) for every change.
- scripts/verify-blocking.sh's mid-stream checks measure what was already in curl's socket buffer at the deny (macOS grows it to 4 MB, and a rate-limited curl reads it for seconds after the cut) and the pf states of its port, so buffered bytes no longer count as a leak; a buffer that cannot be read fails the check.

## [1.4.0] - 2026-10-26

### Changed

- Allow (✓) in the process list now allows the whole app past its own narrower deny rules, as Deny (✗) already wins over its narrower allow rules. Rules for any process still apply.

### Fixed

- The firewall helper checks every 2 seconds that pf still holds Rat's rules and loads them again when they were dropped (sleep and wake, a VPN client reloading pf), and it puts Apple's anchors back in front of a VPN client's anchor that passes traffic first. A firewall whose own rules pass traffic before Rat's is reported in Settings > Security.
- Update Helper is now shown whenever the helper installed or running is not the one in this copy of Rat, compared by SHA-256: after updating Rat, the old helper no longer keeps running unnoticed (Settings > Security, the Inspector and the sidebar say so).
- Denied apps were not blocked after a VPN client (Cloudflare WARP) turned the packet filter off or replaced its main ruleset. The firewall helper now puts pf right within 2 seconds: it turns pf on again (loading macOS's /etc/pf.conf first when another program's leftover rules are in it) and restores the com.apple anchors next to a running VPN's own. Settings > Security says what happened and has Repair Firewall Now. Update the helper (Settings > Security) to get it.
- Windscribe's tunnels (windscribeamneziawg, windscribeopenvpn and the others its helper runs from /Library/Application Support/Windscribe) are listed under Windscribe and are covered when Windscribe is denied.

### Development

- The README is rewritten for 1.3.0 with fresh screenshots from the demo data (`scripts/readme-screenshots.sh`), and a Persian README (`README.fa.md`) is added.

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
