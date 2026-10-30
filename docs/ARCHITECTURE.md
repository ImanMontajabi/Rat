# Rat Architecture

Phase 1 deliverable. **No application source is written for this phase.** This document needs your approval before Milestone 1.

Rat is a clean-room macOS application firewall and network monitor, inspired by Little Snitch. The design below is derived from three sources:

1. Screenshots in `./screenshot` (UI).
2. The public product page (feature list).
3. Static analysis of the installed `/Applications/Little Snitch.app` (beta, build 8013) with REA and Hopper.

Everything is tagged **[observed]** (seen in an artifact), **[inferred]** (reasoned from observations), or **[design]** (our choice). Rat copies no Little Snitch code, assets, or data.

---

## 1. Evidence

### 1.1 Bundle layout [observed]

```
Little Snitch.app                              main app: settings, rules window (SwiftUI)
 ├─ Contents/Components/
 │   ├─ Little Snitch Agent.app                LSUIElement agent: alerts, menu bar, notifications
 │   ├─ Little Snitch Network Monitor.app      SwiftUI + MapKit monitor window
 │   └─ Little Snitch Software Update.app
 └─ Contents/Library/SystemExtensions/
     ├─ at.obdev.littlesnitch.networkextension     NEFilterDataProvider + DNS proxy
     └─ at.obdev.littlesnitch.endpointsecurity     Endpoint Security client (BPF monitoring)

/Library/LaunchDaemons/at.obdev.littlesnitch.daemon.plist   root daemon, Mach service
/Library/LaunchAgents/at.obdev.littlesnitch.agent.plist     per-user agent, KeepAlive + RunAtLoad
/Library/Application Support/Objective Development/Little Snitch/
     ├─ Components/at.obdev.littlesnitch.daemon.bundle/     daemon + codesignaturechecker helper
     │     └─ Resources/InternetAccessPolicies.plist        bundled per-app policies
     ├─ configuration6.xpl                                  rules/profiles/groups (root-only readable)
     ├─ Connections.replog, DNSCache.replog,
     │  RuleUsageStatistics.replog                          append-only replication logs
     ├─ TrafficLog                                          traffic history
     └─ ip-address-database                                 IP geolocation database
```

Evidence: directory listings, `launchd` plists, and `Info.plist` (Agent: `LSUIElement=true`, `LSMinimumSystemVersion=15.4`).

### 1.2 Frameworks per component [observed, `otool -L`]

| Component | Notable frameworks |
|---|---|
| Main app | SwiftUI, AppKit, NetworkExtension, SystemExtensions, ServiceManagement, Network, MapKit, CoreLocation, CryptoKit, LocalAuthentication, Security, SystemConfiguration |
| Agent | SwiftUI, AppKit, UserNotifications, CoreWLAN, CoreLocation, Security, SystemConfiguration, IOKit |
| Network Monitor | SwiftUI, MapKit, Accelerate, CoreLocation, SystemConfiguration, Security |
| Root daemon | Foundation, AppKit, CoreWLAN, Network, NetworkExtension, SystemConfiguration, IOKit, Security |

The product is mixed Swift/Objective-C. UI is SwiftUI/AppKit. No third-party dylibs are linked; everything is system frameworks.

### 1.3 Network extension [observed, REA]

- **Entitlements** (`ev_0b67907e…`): `com.apple.developer.networking.networkextension` = `content-filter-provider-systemextension` and `dns-proxy-systemextension`. It is not sandboxed. It shares an app group with the app and daemon.
- **Filter flow** (strings in `ev_911cbe98…`): `NEFilterDataProvider.handleNewFlow` produces one of five verdicts: allow, drop, pause, inspect packet contents (DPI), or sniff. Verdicts exist for both the new-connection phase and the data phase.
- **Paused flows** are resumed with `resumeFlow:withVerdict:` and updated with `updateFlow:usingVerdict:forDirection:`.
- **Re-evaluation:** log strings show every live flow is re-checked after a rule-tree rebuild, a filter state change (on/off/silent mode), a code-requirement update, or a `newNetworkAlertInfo` change.
- **Process identification:** rules reference `codeRequirements`, `developerTeamNames`, and `lastSeenExecutableByCombinedIdentifier`. This matches the website claim that processes are identified by code signature, not path.
- **IPC:** Swift XPC protocols `LSXPCDaemonProtocol`, `LSXPCClientProtocol`, `LSXPCSnifferServerProtocol`, and `LSXPCSnifferClientProtocol`. `publishLocalXPCListenerEndpoint:` and `getAnyXPCListenerEndpointFor:` show the extension and daemon exchange listener endpoints rather than using only fixed Mach names.
- **DNS proxy provider** exists (`handleNewFlow()` for `NEAppProxy` subclass), which implements the encrypted DNS feature.

### 1.4 Endpoint Security extension [observed]

Entitlement `com.apple.developer.endpoint-security.client`; uses `es_new_client` and `es_respond_auth_result`. The Advanced settings screenshot labels this as *"Berkeley Packet Filter Monitoring: monitoring access to the BPF requires the installation of an endpoint security extension."* Its purpose is to see processes that sniff packets, not to filter traffic.

### 1.5 Agent [observed, `ev_20cc889c…`]

- Classes: `LSAConnectionAlertWindowController` (normal and minimized variants), `LSAConnectionAlertPanel`, `LSANetworkTriggerAlertWindowController`.
- Data: `LSNewNetworkAlertInfo` (what the alert displays), `LSNetworkTrigger` (Wi-Fi network for automatic profile switching), `LSSilentMode`.
- Behavior: alert timeout resolves to a default allow or deny (`ConnectionAlertTimeOut_Title_Allowed/Denied`). Silent-mode connections raise a user notification (`UNUserNotificationCenter`). Alerts can be minimized and the position is persisted.
- The Agent receives alerts over `LSXPCClientProtocol` and sends rule changes over `LSXPCDaemonProtocol`.

### 1.6 Daemon [observed]

LaunchDaemon with Mach service `at.obdev.littlesnitch.daemon`, runs as root, ships with a separate `codesignaturechecker` helper binary and an `XPCServices` directory. Links NetworkExtension, CoreWLAN and SystemConfiguration. I read the daemon's layout and linkage but did not decompile it, so its internal rule-matching and persistence logic is **unknown**.

### 1.7 UI [observed, screenshots]

Network Monitor is a three-pane window:

- **Left:** searchable process list with traffic sparklines and per-row allow/deny toggles; filter chips for incoming/denied connections and a time range (e.g. 1 week); a bottom pane with sent/received totals and a time-scrubbable traffic chart.
- **Center:** MapKit map with arcs from this Mac to remote servers.
- **Right inspector:** a Summary view (counts of denied, unconfirmed, and incoming connections; top processes, domains, countries) switching to a per-process view (path, code ID, user, rules, Internet Access Policy, code signature, connection details, geographic information).
- **Menu:** Group By, Sort By, Show Local Network, Show Network Extensions, Show Connections of Other Users, Float on Top.

Settings window tabs: General, Control Center, Alert, Monitor, APS (automatic profile switching), Security, DNS, Notifications, Update, Registration, Advanced. Advanced includes "Mark new rules as unapproved", "Approve rules automatically", and an optional AI assistant in the alert.

### 1.8 Product features [public site]

Connection alerts, silent mode, rule groups and profiles, blocklists, encrypted DNS (DoH/DoT/DoQ), sound rules, menu bar control center, search, and a command-line tool.

---

## 2. Licensing and paywall

Rat is built from scratch and **has no licensing, trial, demo-mode, StoreKit or paywall code, so there is nothing to remove.** There is no registration tab, no timed demo, and no feature gating.

I did not analyze, and will not plan work around, Little Snitch's own licensing or registration code. That would be about defeating another vendor's protection, not about understanding how a firewall works, and Rat doesn't need it. Rat does not reuse any Little Snitch code or assets either.

---

## 3. Rat target architecture [design]

### 3.1 Processes

```
┌────────────────────────┐   XPC    ┌─────────────────────────┐
│ Rat.app (SwiftUI)      │◀────────▶│ rat-daemon (root)       │
│  rules, settings,      │          │  rule store, profiles,  │
│  network monitor window│          │  traffic log, geo, DNS  │
└────────────────────────┘          └───────▲───────▲─────────┘
┌────────────────────────┐   XPC            │       │ XPC (endpoint exchange)
│ RatAgent (LSUIElement) │◀─────────────────┘       │
│  alerts, menu bar,     │          ┌───────────────┴─────────┐
│  notifications         │          │ RatNetworkExtension     │
└────────────────────────┘          │  NEFilterDataProvider   │
                                    │  (+ DNS proxy later)    │
                                    └─────────────────────────┘
```

Responsibility split follows the observed design: the extension only evaluates a *compiled* rule snapshot and pauses on `ask`; the daemon owns rules and persistence; the agent owns prompting.

**Deliberate simplification:** the first release ships without the Endpoint Security extension and without the DNS proxy. They are separate entitlements and not needed for a working firewall.

### 3.2 Modules (Swift package, `RatFilter` evolves into this)

| Module | Role |
|---|---|
| `RatFilterCore` (exists) | Rules, matching, engine. Pure Swift. Will gain profiles, groups, unapproved state, and a compiled matcher. |
| `RatIPC` | XPC protocols and Codable DTOs shared by all processes. |
| `RatStore` | Rule/profile persistence (JSON now; evaluate SQLite for the traffic log). |
| `RatMonitor` | Flow ledger: per-process / per-domain counters, time buckets, history. |
| `RatGeo` | IP to country/city lookup. Bundled free dataset, not Little Snitch's database. |
| `RatUI` | SwiftUI views: alert, rules list, monitor, settings. |
| `RatExtension` | The `NEFilterDataProvider` target (exists as `RatFilterExtension`). |

### 3.3 Key design choices

- **Process identity:** signing ID + team ID, with path as a fallback option (matches observation 1.3).
- **Rule precedence:** most specific wins, deny wins ties (already implemented; the Little Snitch ordering itself is unknown).
- **Re-evaluation:** on any rule change, re-evaluate paused flows and flows in the data phase.
- **Alert timeout:** configurable default verdict, as observed in the agent.
- **Unapproved rules:** new rules from alerts are flagged until reviewed (Advanced screenshot).
- **Logging:** `os.Logger` with `.notice` for lifecycle and verdict events; no connection contents logged.
- **Updates:** check GitHub Releases for `ImanMontajabi/Rat` (read-only API call, user-initiated or opt-in periodic).

### 3.4 Platform constraints (important)

- A content filter only runs as a **system extension** inside a signed app. The extension needs the Apple-granted NE entitlement. Entitlement availability is something you must confirm in your developer account.
- Your keychain has only an **Apple Development** identity. A distributable build needs a **Developer ID Application** certificate plus notarization.
- For development, `systemextensionsctl developer on` (requires SIP-compatible developer mode on a dev-signed build) lets you test unnotarized extensions locally.
- Minimum macOS: the observed agent requires 15.4. Rat will target macOS 14+ unless you prefer otherwise.

---

## 4. Roadmap mapping

| Milestone | Scope | Risk |
|---|---|---|
| M1 | XcodeGen project (`xcodegen` is installed; `xcogen` is not found on this machine, see questions), host app + extension targets, logging | Signing/entitlement |
| M2 | **High-risk spike:** load the system extension on this Mac, observe real flows through `handleNewFlow`, log them with `.notice`, allow/deny by hard-coded rule | Highest. Proves the platform works before any UI |
| M3 | Daemon, XPC, rule store, re-evaluation | Medium |
| M4 | Agent: connection alert, timeout, minimized alert, notifications | Medium |
| M5 | Rules window (list, edit, unapproved), profiles and groups | Low |
| M6 | Network monitor: ledger, process list, inspector, traffic chart | Medium |
| M7 | Map view + geo database | Low |
| M8 | Settings, silent mode, Wi-Fi automatic profile switching, update check | Low |
| Final | arm64 packaging, icon from `./assets`, Release build, install to `/Applications`, `create-dmg` (installed), `gh release` | Signing/notarization |

Each module gets unit tests. UI gets snapshot tests compared against the reference screenshots. The `Vendor` bundling step is expected to be nearly empty because Rat plans no third-party dylibs (1.2).

---

## 5. Known unknowns

- Daemon internals: rule storage format (`configuration6.xpl` is root-only), matching order, and how the XPC endpoint exchange is authenticated were not analyzed.
- Not examined: DNS proxy internals, blocklist format, geo database format, Network Monitor drawing code, the command-line tool.
- Static analysis only; nothing was observed running.
- The Hopper-based string search is bounded to typed string objects, so absent strings are not proof of absence.

## 6. Questions for approval

1. **Entitlement:** do you have the Network Extension content-filter entitlement on your Apple developer team (or are you willing to request it)? Without it, M2 cannot run.
2. **Distribution:** is a Developer ID certificate available for the final release, or should the first release be explicitly unsigned/dev-only?
3. **Tooling:** `xcogen` isn't installed; `xcodegen` is. Should I use XcodeGen?
4. **Scope:** OK to defer Endpoint Security and DNS proxy to after v1?
5. **Minimum macOS:** 14, or match the observed 15.4?

---

## 7. Revision 1: no paid developer account

**Decision input (from the project owner):** no Apple Developer Program membership, so no Developer ID and no Network Extension entitlement. Users will run an unnotarized app from GitHub Releases.

**Consequence.** Everything in sections 3.1 and 3.4 that depends on `NEFilterDataProvider` (the system extension, `resumeFlow` pausing, per-process allow/deny before a connection is made) is **not available**. The NE content-filter entitlement is granted only to paid-program teams and is embedded in a provisioning profile; it cannot be self-signed. Disabling SIP/AMFI would work on one dev machine but cannot be shipped to users, so it is rejected.

**What Rat v1 is instead: a network monitor with reactive enforcement.** Entitlement-free mechanisms:

| Capability | Mechanism | Limit |
|---|---|---|
| See every process's connections (process, remote IP/port, protocol, state) | `libproc` (`proc_pidfdinfo` / `PROC_PIDFDSOCKETINFO`) polling | Other users' processes need root. Short-lived connections can fall between samples. |
| Traffic volume per process | `nettop -P -L` (or `NetworkStatistics` private API, rejected as unstable) | Sampled counters. |
| Domain names | Reverse of observed DNS answers / reverse lookup | Best effort. |
| Geolocation / map | Bundled IP database + MapKit | Accuracy limited by the dataset. |
| New-connection alerts | Diff of successive samples, shown by the agent as a notification/alert | **Reactive:** the connection has already started when the alert appears. |
| Blocking | `pf` anchor loaded with `pfctl`, plus `pfctl -k` to kill existing states | `pf` cannot match by process, only by user/group and destination. A deny therefore blocks that destination **for all processes** (optionally scoped to a user). Needs admin rights, requested through a standard macOS authorization prompt. |

**Honest product positioning:** Rat v1 shows and blocks, but it is not a Little Snitch-grade per-process firewall. The README and UI must say so.

**Architecture changes**

- `RatNetworkExtension` is removed from v1. The existing `RatFilterExtension` package target stays dormant so it can be shipped if a paid account ever exists.
- The daemon becomes an optional root helper installed on demand. Because Rat is ad-hoc signed, privileged actions use an admin authorization prompt per session instead of a registered `SMAppService` daemon (registration of an unsigned helper is unreliable).
- New module `RatMonitor` (connection sampler); `RatFilterCore` rules become *destination* rules that compile to `pf` syntax.
- Distribution: ad-hoc signed `.dmg` with a README note: right-click, Open (or `xattr -d com.apple.quarantine`). Updates check GitHub Releases.
- Minimum macOS: **14**. Endpoint Security and DNS proxy: deferred indefinitely (both need entitlements).

**Revised M2 spike:** sample real connections on this Mac with `libproc`, verify a connection we create ourselves is observed, and log with `logger.notice`.

---

## 8. Revision 2 (v1.0.0): what changed from section 7

| Area | v0.2 | v1.0 |
|---|---|---|
| Rules | Allow/deny per app only | Full `RatFilterCore` engine: app / team ID / signing ID, domain, exact host, IP, port range, protocol; specificity precedence; groups; profiles; network triggers; unapproved review; JSON import/export |
| Prompts | None | Floating `NSPanel` alert (scope and lifetime), Alert Mode or Silent Mode |
| Menu bar | None | `NSStatusItem` with throughput, profile and mode switchers |
| Geolocation | Opt-in `ipwho.is` lookups | Offline DB-IP Lite `.mmdb` in `Contents/Resources/Vendor`, own reader (`RatGeo`); the Mac's position from its time zone |
| Blocking | Manual "Apply" per change | Optional root helper (two LaunchDaemons): blocklist applied as soon as it changes; system-wide socket snapshots |
| Storage | `state.json` | One folder, `com.imanmontajabi.Rat`: `state.json`, `rules.json`, `blocklist.txt`, `system-sockets.txt` |

Design decisions:

- **Reactive alerts.** The sampler sees a connection after it starts. Alerts are suppressed for the first 12 s after launch (existing sockets) and for private addresses, and deduplicated per app and domain.
- **`approved` is a review marker.** Rules created from alerts stay active with a blue dot while *Mark new rules as unapproved* is on; imported rules arrive disabled and unapproved so a downloaded rule file cannot silently change behaviour. Imported rules lose profile scopes the local set does not have.
- **Helper trust model.** The daemon script is root-owned, reads a user-writable blocklist but accepts only syntactically valid IP addresses, and the snapshot file it writes is owned by the user with mode 600. The helper is opt-in, explained before the admin prompt, and removable in one click.
- **Profile switching** keys on the Wi-Fi name when macOS reveals it (needs Location access) and otherwise on the default gateway.

Still out of scope: per-process blocking and pre-connection prompts (Network Extension entitlement), DNS encryption, blocklist subscriptions, Endpoint Security.

---

## 9. Revision 3 (v1.0.1): Settings and Rules windows rebuilt from Little Snitch's own resources

The first versions guessed at the UI from screenshots. v1.0.1 follows the app's own localisation tables (`Settings.strings`, `RulesWindow*.strings`, `RulesCategory*.strings`, `FilterScopes.strings`, `ProfileInspector.strings`, `RuleLifetimeOption.strings`), read from the read-only mounted DMG. These record labels and structure only, not layout.

| Little Snitch | Rat |
|---|---|
| Settings tabs General, Control Center, Alert, Monitor, APS, Security, DNS, Notifications, Update, Registration, Advanced | Same order and wording, minus DNS (no DNS encryption) and Registration (no licensing). Security holds the firewall helper because Rat has no code-signing lock settings. |
| Rules window sidebar: Rules, Suggestions, Profiles, Rule Groups, Networks, Maintenance, Blocklists | Rules (All, Unapproved), Profiles, Rule Groups, Known Networks, Maintenance (Invalid Rules). Suggestions, redundant/unused rules and blocklists are not implemented. |
| Rules table: Active, Process, Description, Status | Same columns; Status shows unapproved (blue dot) and temporary |
| Operation mode: Alert, Silent Allow, Silent Deny | Same; **Silent Allow is the default** |
| Unknown network: Ask, Do Nothing, Deactivate, Activate profile | Ask, Do Nothing, Activate profile (Rat always has an active profile) |
| Monitor toolbar: view menu (Group By, Sort By, Show Local Network, Show Network Extensions, Show Connections of Other Users, Float on Top), traffic chart, inspector | Same three buttons and menu entries, all functional |

Behaviour fixes in this release: alerts re-validated against the rules every tick, so an app with a whole-app Allow or Deny never prompts; alert scope defaults to *This App (Any Server)*; IP addresses are never stored as "domains"; the traffic chart tiles its window and fits it to the data that exists; versioned binaries (`…/claude/versions/2.1.308`) resolve to their tool; app extensions (`.appex`) are listed separately like Little Snitch's EXT rows.

## 10. Revision 4 (v1.0.2 to v1.0.4): blocking a denied app by its sockets

Chasing the server addresses of a denied browser cannot work: Chrome and Firefox rotate CDN addresses, fall back to IPv6 and move QUIC streams. Worse, an address is shared by every app on the Mac. v1.0.2 and v1.0.3 still put the servers a denied app talked to into a global `<rat_blocked>` table, and one Deny on Chrome ended up blocking 1.1.1.1, 8.8.8.8 and 9.9.9.9 (DNS) for every app. **From v1.0.4 Rat never blocks a remote address, in any mode.** The code that recorded them is gone.

Deny is enforced by the root daemon `rat-enforcerd` (a `KeepAlive` LaunchDaemon installed with the helper), which owns the `com.apple/rat` anchor:

1. **Grouping.** Every helper process is attributed to its app: the outermost `.app` or `.AppBundle` in the path (Chrome Helper variants, Firefox `plugin-container`, `Steam Helper`, `steam_osx`, `ipcserver`), and system XPC services such as `com.apple.WebKit.Networking` follow `responsibility_get_pid_responsible_for_pid` to Safari. Only system services borrow their client's identity, so `curl` run from a Terminal stays `curl`.
2. **Ports of denied apps.** Rat writes the apps that are denied outright to `denied-apps.txt`: a Deny from the process list (it wins over the app's narrower allow rules, v1.0.5), or Silent Deny for apps without allow rules. The daemon reads the process list every 3 ms and **every socket of every denied process on every pass** (Chrome's ~35 processes take about 0.05 ms; descriptors are reused and a socket only gets its port when it connects, so nothing read earlier is trusted), and blocks their local ports. Entries are matched by path prefix after resolving symlinks (`/Applications/Safari.app` points into the Safari cryptex).
3. **Ports of denied sockets.** Sockets that a rule denies (for example one domain for all apps) are written by Rat to `denied-ports.txt` every pass; the daemon trusts the file for 10 s, so a crashed Rat cannot leave ports blocked.

The anchor contains only these stateless rules (no table, no `pass`):

```
block return-rst  out quick on ! lo0 proto tcp from any port { … } to any no state
block return-icmp out quick on ! lo0 proto udp from any port { … } to any no state
block drop        in  quick on ! lo0 proto { tcp udp } from any to any port { … } no state
```

Outgoing TCP gets an RST and UDP an ICMP unreachable, so the app gives up instead of retransmitting. Because the rules are stateless and there is no `pass` rule, a connection that is already open dies on its next packet, while other apps (even to the same server) are never evaluated against it. A `pass … no state` rule in the anchor was considered and rejected: a `quick` pass would end evaluation and override every later block rule on the Mac. `pfctl -k` (kill states by address) is not used either, because it would cut other apps' connections to the same server. On start the daemon flushes the anchor, and deletes a `blocklist.txt` left by an older version.

pf cannot match a process, so the port layer reacts to a socket after it exists. A SYN may leave before the ports are loaded (about 8 ms); the server's answer is dropped when it arrives, so a connection to a distant server fails, but one to a server a few milliseconds away can complete its handshake first. `scripts/verify-blocking.sh` (needs `sudo`) checks the mid-stream case (a denied and an allowed process downloading from the same address, plus DNS to 1.1.1.1, 8.8.8.8 and 9.9.9.9) and measures the fresh-process case. Closing that gap needs a Network Extension.

The map never zooms tighter than 15 degrees (v1.0.3).

### v1.0.5: why Deny did nothing in 1.0.4

Two bugs, both between the UI and the daemon; the daemon itself worked (the scripted test passed).

1. **A test changed the real preferences.** `Enforcer.autoApply` was persisted in `UserDefaults.standard`, and a unit test (which runs inside the app as test host) set it to false. From then on Rat wrote no deny list. The switch is gone (with the helper installed, Deny is always enforced), and all preferences go through `Preferences.store`, a separate suite under XCTest.
2. **Old allow rules hid the Deny.** Chrome had narrow allow rules from 1.0.0 alerts (`1e100.net`, a few addresses). `deniedAppPaths` skipped any app with an allow rule, so the list showed Chrome as denied while nothing was blocked. A process-list Deny now wins; the narrow rules are kept but overridden, and the inspector says so.

To make such failures visible, the daemon publishes `/var/run/com.imanmontajabi.rat.enforcer.json` (pf enabled, anchor evaluated, per denied app: processes matched and connections cut) every second; Rat shows it in Settings > Security, the inspector and the list footer, and `scripts/rat-status.sh` prints it. A watchdog re-enables pf if another tool disables it. If another ruleset keeps state for a connection that becomes denied, that state is killed (`pfctl -k local -k remote`; macOS' pfctl cannot kill by port).

Verified live on the real app: Chrome (35 processes) and Steam (13) denied by Rat's own rules, Safari denied through the same rule the red X creates; the anchor held 124 stateless port rules and no table, pf held 0 states; a fresh Chrome instance failed with `net::ERR_CONNECTION_RESET` and Safari could not open example.com (and could again once allowed), while curl, python3 and DNS to 1.1.1.1, 8.8.8.8 and 9.9.9.9 kept working. The daemon uses about 14% of one core while denied apps with ~50 processes run (3 ms pass).

## 11. Revision 5 (v1.1.0): connections through local proxies

With `http_proxy`, `https_proxy` or `ALL_PROXY` pointing at a local SSH tunnel (`ssh -D 1080 vps`) or proxy, a firewall that looks at sockets sees only the client talking to `127.0.0.1:1080` and `ssh` talking to one server address. Little Snitch shows exactly that. But the hop between the client and the local proxy crosses lo0 before anything is encrypted, so the client's first bytes name the real destination in plain text.

1. **Capture on lo0 (root daemon).** `rat-enforcerd --proxied /var/run/com.imanmontajabi.rat.proxied.json --owner-uid <uid>` opens a BPF device on lo0 with a classic BPF program (`LoopbackFilter`) that accepts only TCP segments whose payload starts like a proxy request: the HTTP methods (`CONNECT`, absolute-URI `GET http://…` and the rest), a SOCKS5 CONNECT request (`05 01 00`) or a SOCKS4 CONNECT (`04 01`). Proxied downloads, TLS records and local databases stay in the kernel; accepted packets are cut to 600 bytes. `ProxyHandshake` parses them strictly (a local web server's `GET /` with a `Host` header is not a proxy request, a SOCKS request with trailing bytes is rejected). The two ends of the loopback connection are then looked up with libproc: the client process and the proxy process.
2. **Privacy.** Only connections of processes owned by `--owner-uid` (the user who installed the helper) are kept, and the file is written in `/var/run` (root-owned, so no link can redirect the write; the temporary file is opened with `O_NOFOLLOW|O_EXCL`), handed to that user with mode 0600. No payload beyond the request line or SOCKS request is read or stored. Closed connections stay listed for 30 s so a one-second `curl` still reaches Rat.
3. **Command-line fallback (no helper, or a connection opened before the helper ran).** For a client's loopback connection to a port that is a known proxy, or that its `--proxy`/`-x`/`--socks5*` arguments or `*_proxy` environment variables name, Rat reads `KERN_PROCARGS2` and takes the hosts of `scheme://host` arguments (curl, wget, `git-remote-https`). Only those hosts and the proxy settings are kept, never other arguments or variables.
4. **Display.** The unmasked destination replaces the client's `127.0.0.1:1080` socket in its connection list, with a badge: *via ssh proxy (127.0.0.1:1080 → 203.0.113.5)*. The server is the proxy process's one connection off the Mac. With several (a proxy that connects directly to many targets) none is named. `ssh` and its server stay listed as usual. The map draws This Mac → proxy server → destination (the second hop dashed, proxy pins marked), and a single dashed line when the proxy's server is unknown. To place a name on the map Rat resolves it with the Mac's DNS, in the background. That reveals the name to the DNS resolver, which a proxy with remote DNS (`socks5h`) was hiding it from, so Settings > Monitor can turn it off.
5. **Blocking.** For every denied process the daemon now also takes its loopback TCP connections to another program (a local proxy, an `ssh -L` forward, any local server) and blocks their local ports on lo0:

```
block return-rst out quick on lo0 proto tcp from any port { … } to any no state
block drop       in  quick on lo0 proto tcp from any to any port { … } no state
```

Connections between the app's own processes (to a port the app listens on) and connections other programs open to the app are left alone. On lo0 each client port belongs to one connection, so nothing else is touched; there is still no address rule and no `pass` rule. Loopback states are never killed (`pfctl -k 127.0.0.1 -k 127.0.0.1` would be every local connection). A rule that denies the real destination (for example a domain for one app) makes Rat write `lo0 <client port>` into `denied-ports.txt` for live connections only (the port of a closed one may already belong to another program).

Verified live with `scripts/verify-blocking.sh` phase 3 (a local HTTP CONNECT/SOCKS5 proxy, `scripts/test-proxy.py`). The daemon published `example.com:443 (HTTP CONNECT)` and `www.wikipedia.org:443 (SOCKS5)` with the proxy process, in a 0600 file. A denied curl's proxied download stopped mid-stream while an allowed python3 kept downloading through the same proxy, and 10/10 fresh denied curls through the proxy were blocked (the proxy must reach the server before answering, so the port is loaded in time). In the installed app, a denied curl failed 6/6 through the proxy, and a curl with a rule denying `ovh.net` still reached Wikipedia through the proxy while its `proof.ovh.net` download was cut within about two seconds (Rat's pass interval). Limits: UDP through a proxy (SOCKS5 UDP ASSOCIATE) is not unmasked or blocked on lo0; destinations inside a tunnel that does not speak a proxy protocol (`ssh -L`, a VPN) cannot be named, though a denied app's connection to them is still cut; the proxy itself has already received the first request when the cut happens. With another VPN or firewall tool active (Windscribe connected, then disconnected, reloaded pf), a second run of the script showed pf evaluating Rat's rules for only a few packets of an already-open connection, so a denied curl kept downloading mid-stream; every new connection (15/15 direct, 10/10 through the proxy) was still blocked. Rat cannot make pf see packets that another component routes around it.

## 12. Revision 6 (v1.2.0): the five feature issues

1. **Port names (#1).** `PortNames` holds the reviewed table proposed in the issue (276 ports), with UDP overrides: 443 is QUIC and 853 is DoQ. Some entries were corrected against the proposal:
   - 2483/2484 are Oracle's plain and TLS listeners.
   - 7000 is AirPlay, where macOS' AirPlay receiver listens.
   - 9100 is JetDirect printing.
   - 16379 is Redis' cluster bus.
   - 62078 is iPhone sync.

   Unverified entries were dropped. The UI says "usually": a port does not prove what a connection carries.
2. **Subprocess and system services (#5).** Every remote keeps its socket's pid and process, and the inspector shows *via Google Chrome Helper (pid 812)* when that is not the app's main executable. The macOS row stays one row (option b), with its connections grouped by service. Services that work for many apps are marked as such and never attributed to a guessed app: mDNSResponder, nsurlsessiond, apsd, trustd, cloudd, networkserviceproxy and WebKit networking without a responsible app. Without a DNS proxy (a Network Extension), a DNS lookup cannot be tied to the app that asked. The macOS row has no one-click Deny: denying every system service would cut DNS for all apps.
3. **Network owner (#4).** DB-IP IP to ASN Lite (CC BY 4.0, 9 MB) is bundled next to City. `ASNDatabase` also reads MaxMind GeoLite2-ASN, since both use the same fields. The owner is shown as the network's owner, not the service's vendor.
4. **GeoIP files (#3).** Settings > GeoIP lets the user choose a City or ASN `.mmdb`, or download the latest DB-IP Lite file. A file is accepted only if it opens and answers like that kind of database for well-known addresses. It is copied into `GeoIP/` under a new name (the reader memory-maps files, so a file in use is never overwritten) and loaded without a restart. A missing or broken choice falls back to the bundled file. The pane shows the type and build date and flags data older than three months. MaxMind files must be brought by the user (their licence forbids redistribution), and no licence key is stored. Because a chosen file is untrusted input to the hand-written reader, every tree and data read is bounds-checked, type sizes are validated, and a decode budget stops pointer loops and giant maps. Tests feed it truncated and random files.
5. **VPN and system proxy (#2).** The sampler now keeps each socket's local address. A socket whose address belongs to a tunnel interface (utun, ipsec, ppp, tun, tap, wg) goes through the VPN, so split tunnels are told apart per socket. The VPN is named from the process holding the tunnel's kernel-control socket (the root helper publishes these as `tunnels` in its status, since VPN daemons often run as root), matched as whole words against the 105 known VPN and proxy apps from the issue. Failing that, Rat uses the System Settings service name, the owner's app name, or the interface name. Enabled HTTP, HTTPS and SOCKS system proxies come from `SCDynamicStoreCopyProxies`, and a connection to one, a local proxy app included, is marked *via System … Proxy*. PAC files are not evaluated, and a proxy set inside one app is invisible. Rat never blocks the proxy's address, so the issue's concern that a Deny could cut every proxied app does not apply.


## 13. Revision 7 (v1.5.0): the daemon follows rules for one process or connection

1.5.0 lets a rule name one process of an app (`Rule.executable`) or one connection of a process (server, port, protocol), and the process list's ✗/✓ decide the narrowest level first (`RuleEngine.decide`). Until now only apps denied as a whole reached the daemon's 3 ms pass; a rule's deny reached pf through `denied-ports.txt` after Rat's 1.5 s pass, when the connection was already open. On a Mac where pf misses packets of established flows that cut nothing.

Rat now also writes `deny-rules.json` (`DaemonRules`, RatFilterCore): the active rules (allow rules too, they decide as well), the names Rat judged servers by (address → name, `""` for none; kept after a connection closes, at most 2048), the apps' code signatures and the user's local ranges. It is empty while no deny rule names a process path, so no names leave Rat then. The daemon reads it next to `denied-apps.txt` (`--rules` overrides it, so the 1.4.0 LaunchDaemon needs no change), as untrusted input: at most 8 MB, and a file that does not parse counts as no rules.

1. **Which processes.** Every new process is grouped with `ProcessGrouping.owner`, the same function Rat's list uses (`AppIdentity.resolve` maps it to names), so the daemon's app key is the list's `ruleKey`. A process is watched when it or its app is inside a path a deny rule names (an app, a helper, a system service such as `/usr/bin/curl` in the `macOS` row). A deny for any process, or by code signature alone, is left to Rat's pass: it would mean reading every process. A deny rule for one process (or one connection of it) also names the executable, and only that executable is watched (`SocketJudge.watchList`): a socket is denied only by a deny rule that matches it, so the app's other processes never need reading. Before, a ✗ on Safari's SearchHelper had the daemon read the sockets of every Safari process every 3 ms.
2. **Which sockets.** Every socket of a watched process is read on every pass, like a denied app's, and judged by `SocketJudge` with the rule engine itself. A socket's verdict is kept while it exists and judged again when the file changes. Listening sockets and loopback connections are skipped.
3. **Only what is certain.** The daemon does not know a server's name until Rat has named its address, nor where an unconnected UDP socket will send. `RuleEngine.decide(_:unknown:)` then counts rules that do not deny as matching whatever the unknown part is, and deny rules only when they need none of it. Matching more allow rules and fewer deny rules never turns the decision into a deny, so a deny there is a deny for every possible name: the daemon never blocks what Rat's pass would allow. For example an app ✗ with a ✓ for `api.example.com` leaves a socket to a not-yet-named server alone until Rat names it; one named otherwise is cut at once.
4. **The local network** is judged as in Rat's pass: rules from alerts or the Rules window leave it alone (`LocalNetwork`, moved into RatFilterCore with `LocalRanges`), a ✗ in the process list covers it, as an app's ✗ does.
5. **What is blocked** is still only the local ports of those sockets, with the same stateless anchor rules, and a state another ruleset kept for one is killed (`pfctl -k local -k remote`) as before. No address is put into pf. `denied-ports.txt` is still written, so rules the daemon cannot follow (a domain for any process) keep the 1.5 s path.

The status file reports `ruleDenied` (per app: processes and sockets cut by rules) and `denyRules`; `scripts/rat-status.sh` prints both and the rules in the file, and `scripts/verify-blocking.sh` phase 4 tests a process rule (mid-stream and fresh curls, python3 to the same address unaffected) and a connection rule by address and by name (curl to other servers unaffected).

**Mid-stream checks and the socket buffer.** `verify-blocking.sh` used to call a denied stream alive when the file curl wrote still grew 1.5 s after the deny. curl runs at `--limit-rate 400k`, and macOS grows a socket's receive buffer up to `net.inet.tcp.autorcvbufmax` (4 MB): netstat showed 1.4 to 3.1 MB waiting in curl's Recv-Q, which curl keeps reading for seconds after pf cut the connection, and then it exits with a reset. The 1.5.0 run read 0.86 MB (phase 1) and 0.94 MB (phase 4a) after the deny, less than the buffer held. The check (`midstream`) now measures the Recv-Q at the deny and passes when curl stops for good having read no more than that plus 64 KB, and it prints the pf states of curl's port before and after (pf looks up states before any rule; the daemon kills those it finds, `pfctl -k local -k remote`, after loading a port).

**CPU of the fast pass.** While anything is watched the daemon passes every 3 ms, waking from a sleep each time, and work done just after a wake runs on cold caches: listing every process (`proc_listallpids`, about 1,000 on a typical Mac) took 11 µs in a tight loop but about 160 µs per pass, a third of the daemon's CPU. A new process is first in the kernel's list, so each pass reads only the newest 32 pids into a reused buffer (`ConnectionSampler.newestPIDs(into:)`, about 20 µs) and lists everything only when one of them is unknown, and four times a second anyway (the pass that forgets exited processes). Processes younger than a second are still read every pass, so a fork that becomes a denied program is noticed; one that exited is left for that cleanup, as before. The list of watched processes is rebuilt only when it changes, not from the 1,000-entry table on every pass.

The pass rate has three steps: every 3 ms while a denied or watched process runs (`interval`), every 20 ms while something is denied but none of it runs (`standbyInterval`), every second with nothing to enforce (`watchedIdleInterval`; 0.25 s, `idleInterval`, when `FileWake` cannot watch every folder of Rat's files). The middle step is new: before, a deny for an app that was not running left the daemon at 0.25 s, so the app's first connections could go unseen that long; a ✗ on a program in the macOS row (curl) was always fast only because every system service was watched. Measured with the daemon's pass loop run as the user (pfctl stubbed), old → new: the user's ✗ on Safari's SearchHelper 13.3 % → 4.9 % CPU, a denied program that does not run 0.5 % → 1.9 %, no deny rule 0.1 % either way; a fresh curl under a connection rule had its port loaded at most 23 ms after its socket appeared (median 2–3 ms). The installed helper with the user's rule: 14.5 % → 3.6 %.

**Idle helper (1.6.0).** With nothing enforced, the watchdog still ran `pfctl -s info` and `-s rules` every 2 s (5-65 ms each, most of the time the helper was awake: 244 of the loop thread's 252 awake samples in `sample`), and the loop woke every 0.25 s although `FileWake` already ends its sleep on any change to Rat's files. Nothing enforced means nothing denied, no deny rule for a process and no port in the anchor, and pf off then blocks nothing, so the check comes every 10 s (`idleWatchdogInterval`) and the sleep lasts a second. The pass that starts enforcing loads its ports first and checks pf on the next pass (a check before the load made the first deny 5-65 ms later), then every 2 s as before; a repair request checks at once. The tunnel scan for VPN names keeps its 5 s and the status file its second. Installed helper with nothing enforced: 6 `pfctl` runs in 30 s (`fs_usage -f exec`), against 30 at a check every 2 s; one idle wakeup in 62 s (`top`'s IDLEW is a total since the process started: the old helper's 474 were about six hours' worth, one every 46 s, not a rate); 0.5 % CPU and 10 MB either way, since `pfctl`'s time is its own.

**File descriptors (1.5.0 fix).** The daemon's loop and `ProxyWatch` run on detached threads, whose autorelease pool is drained only when the thread ends, and Foundation autoreleases the file handle of the pipe `captureCommand` reads pfctl's output from. So every `pfctl -s …` kept a descriptor open. After a few hundred the daemon reached launchd's soft limit (`launchctl limit maxfiles`: 256): pfctl could no longer be started, `-s info` came back empty, the watchdog reported pf as off and nothing it loaded reached pf, so denied apps were no longer blocked until the helper was restarted. `runCommand`, `captureCommand`, each pass of `loop` and each read of `ProxyWatch` now run in an autorelease pool of their own (`CommandRunnerTests` runs 300 commands on a detached thread and checks the descriptors).

## 14. Revision 8: the three levels in the views

1.5.0's rule engine knew three levels (an app, one process, one connection of a process); only the app's row had a ✗/✓. Now every level has one, and the inspector and the Rules window follow the selection.

1. **One target per row.** `RulesModel.Target` is a row as rules see it: the app's `ruleKey`, one executable, one `Endpoint`. `AppEntry.ruleTarget(process:remote:)` makes it from the list (the executable is the path Rat saw the process run from); a connection inside the local network gets none, since Rat's pass never judges it, so a rule there could not hold. `Ledger.setPolicy(_:for:)` writes the rule of the target's level with the 1.5.0 setters, so enforcement is the same code (`deny-rules.json`, `denied-ports.txt`). A connection row is one server, port and protocol of a process (`RemoteHost.id`; the sockets of one row add up their bytes). It used to leave the protocol out, so a process with a TCP and a UDP (QUIC) connection to one server, as browsers have on 443, had one row showing whichever socket the kernel listed first: a ✗ made a rule for that protocol, and when the order changed on a later pass the row showed the other one with no ✗, as if the click had been lost, and Rat's pass cut both sockets.
2. **What a row shows.** `RulesModel.rowPolicy` gives the row's own choice and the one it follows without one: a connection its process's, then its app's; a process its app's. That is the order `RuleEngine.decide` takes the list's rules in. Rules from alerts are not a row's choice. `PolicyToggle` draws an own choice in full colour and a followed one muted (accessibility value `on`, `inherited`, `off`); clicking sets the row's own, clicking the active one clears it. Services that work for every app (`SharedServices`: mDNSResponder, apsd, …) show a lock, as the macOS row does.
3. **The inspector** lists `RulesModel.rules(for: Target)`: for an app, the rules naming it or a program inside it; for a process, those naming its app (with no other process) or itself; for a connection, every rule that matches it, rules for any process and disabled ones included, with the one that decides it now marked (`decidingRule`). Its ✗/✓ sets the same target as the list.
4. **The Rules window.** Manage Rules… sets `RulesModel.focus`; the window takes it on appear or on change and shows that target's rules. The new Apps / Processes section lists the apps the rules name, each with the processes its rules name (and the focused connection). New Rule starts from the target (`newRule(for:)`: app, executable, server by name or address, port, protocol), and the rule editor has an "Only this process" field for `Rule.executable`.
5. **One name per program (found live).** A ✗ on Safari's `com.apple.Safari.SearchHelper` was saved as `/System/Library/PrivateFrameworks/…` and never blocked: the daemon reads the kernel's path (`proc_pidpath`), `/System/Volumes/Preboot/Cryptexes/Incoming/OS/System/Library/…`, while Rat had taken that process from the root helper's snapshot, whose paths come from `ps` (the name a program was started by: a symlink into a cryptex, `Versions/A` left out, a bare name; 67 of 972 processes differed). Rat now names a snapshot's processes by the kernel's path, as its own sampler does, and rules, `SocketJudge`, `DeniedApps` and the views compare paths through `ProgramPath` (RatFilterCore), which drops the cryptex prefixes (`…/Cryptexes/OS/`, `…/Cryptexes/Incoming/OS/` → `/`; the App cryptex → `/System/Cryptexes/App/`), so rules saved under either name, and the kernel's name after a security update moves the cryptex, still match. A ✗/✓ also cuts the ledger's 1.5 s nap short (`Ledger.requestPass`), so open connections are judged by the new rule at once.

## 15. Revision 9: who started a connection

The list showed every socket with a remote end as a connection this Mac made. A connection a peer made to a listening port (ssh into the Mac, Steam's Remote Play, a dev server reached from a phone) was a row to the peer's ephemeral port with a ✗/✓ that read as "block this server", and in Alert Mode it raised an alert as if the app had connected out.

1. **Incoming.** One socket does not say who started it. `SocketDirection.mark` (RatMonitor) calls a TCP connection incoming when its local port is held by a listening socket on the same address or on any address (`*`, `0.0.0.0`, `::`; an IPv4 address an IPv6 socket reports as `::ffff:a.b.c.d` matches its plain form). The listener may be another process's: launchd listens for `sshd` and hands each connection to the session it starts, so the listeners of every process count. The root helper's snapshot now keeps listeners too (`SystemSnapshot.parse(_:listeners: true)`; `lsof` lists them as `*:22` with `ST=LISTEN` and no `->`). UDP has no listener or handshake to go by, so a UDP socket is never called incoming. An outgoing socket bound to a listening port on purpose (some peer-to-peer programs do) would be called incoming; nothing else is.
2. **Rows.** A peer's connections to one port of this Mac are one row (`in|address:localPort/proto|process`; each comes from its own ephemeral port), separate from the app's own connections to the same peer, with `RemoteHost.port` the port of this Mac and `incoming` set. The row has a blue `↓ Incoming` tag and no ✗/✓ (`ruleTarget` is nil): rules decide what this Mac connects to. It is still judged, by the socket's own ports as the helper judges it, so an app's ✗ shows it denied (the helper blocks every socket of a denied app, listeners included); it never raises an alert or counts as unconfirmed. A local proxy tag is never put on an incoming row (a peer that connected to a proxy does not go through it).
3. **Streams.** `StreamDetector` keeps each socket's first sighting and when its received count last grew. A socket is a stream once it has been open 30 s, received at least 32 KB and 8 times what it sent, and is still receiving (grew in the last 10 s). Its row gets a blue `↓ stream` tag and keeps its ✗/✓ (this Mac opened it: blocking a tracker's push channel is useful). Rat sees byte counts per socket, so a server push (Server-Sent Events), a download and a media stream look the same, and a WebSocket that talks both ways is not a stream; the tag says only what the counts show. Sockets that close are forgotten on the next pass.
4. **Where they show.** The tags follow the route tags in a connection's row and in the inspector, which also says the direction and calls the port "on this Mac". App and process rows leave them out (`RouteSummaryBadges` keeps its room for routes). The Only Incoming chip keeps apps that listen or hold an incoming connection.

## 16. Revision 10: flags and Hide Local

1. **Flags.** The City database gives each address an ISO 3166-1 alpha-2 country code; `GeoPoint.countryCode` keeps it (the Mac's own point takes its region's code), and `Flag.emoji` turns it into the flag by mapping each letter to its regional indicator symbol (`DE` → 🇩🇪). Only real region codes get one (`Locale.Region.isoRegions`, plus `EU`; not `ZZ`, the databases' unknown). `GeoPoint.place` ("🇩🇪 Berlin, Germany") is what the inspector's Location, Proxy at and Geographic Information show; connection rows put the flag before the host (hidden from VoiceOver, which reads the place in the tooltip) and carry the place as their tooltip; the Summary's Top Countries, the country groups and the map's pin labels put it before the name. The map's accessibility value (`map-places`) stays city names.
2. **Hide Local.** `isLocalTraffic` is `LocalNetwork` (loopback, private, link-local, the user's ranges) plus multicast and broadcast (Bonjour's 224.0.0.251 and ff02::fb, SSDP's 239.255.255.250, 255.255.255.255) and mDNS (UDP 5353) at any address. `RemoteHost.isLocal` is that, except for a connection through a proxy (`isProxied`): a loopback socket to Tor or `ssh -D` carries traffic that leaves the Mac. The labeled Local switch beside the search field (`show-local`, on while local connections are shown; until 1.6.0 an unlabeled `house.slash` chip inside it, `hide-local`, which users did not find) sets `MonitorFilter.hideLocal` to its inverse, which starts from and is saved to `AppSettings.hideLocal`. It drops local connections from the tree, the map (`MonitorFilter.matches`) and the Summary, apps whose connections are all local (`AppEntry.onlyLocal`; an app with no connections listed stays), and processes whose connections were all local (one with traffic and none listed stays). It is a standing preference, not a filter: the Summary does not say "Filtered" and keeps the session's totals, counting only the connections and apps left. The older "Show Local Network" view option is unchanged: it hides apps that have only local connections and no traffic.

## 17. Revision 11: traffic on the map, and what Rat costs

1. **Rates per line.** Each row's rate is how much its sockets' nettop counters grew since the last pass (`RemoteHost.rateIn`/`rateOut`, from `Ledger.rowBytes`, keyed by app and row); a row whose sum dropped (a busy socket closed) counts as no traffic, not negative. `MapPane.graph` sums the rates of the connections each line stands for (both hops of a proxied one), and `FlowDirection` names a line's traffic: idle below 512 B/s each way, `.up` or `.down` when one way carries four times the other (a download's ACKs do not make it two-way), `.both` otherwise.
2. **Pulses.** `FlowOverlay` converts each moving line's coordinates into view points (`MapProxy`, coordinate space `rat-map`) and hands them to `PulseHost`, an NSView that draws each pulse as a laser tracer (1.6.0; dots and a three-dot trail before): a soft wide glow, a beam with a fading tail and a white-hot core, all `CAShapeLayer`s of the line's path whose `strokeStart`/`strokeEnd` follow the head, a haloed head dot moved along the path, and a ring that ripples out where the tracer lands (`MapFlows.Tracer`: the head crosses the line in the first 80 % of a 2.4 s trip, the tail drains and the ring grows in the rest). Each layer runs one repeating `CAAnimationGroup` (`preferredFrameRateRange` 24–30 FPS), so Core Animation draws the frames outside SwiftUI and MapKit. The view clips to the map (`masksToBounds`): a line to a server off the map's edge never draws over the list or the inspector. Sent traffic is purple and runs out from This Mac, received is blue and runs in from the server; a two-way line carries both, half a trip apart, and a line at 256 KB/s or more carries two pulses each way. A line whose points and flow did not change keeps its layers (no restart); a camera move rebuilds them (`MapCameraTicks`), and so does a resize, which moves every point without moving the camera: once on the next turn of the main queue and again 0.3 s after the size stops changing (`MapCameraTicks.resized`), since the map takes its new size only after the layout pass, and only at the end of the inspector's slide. Before, the paths kept the points of the window's size at launch (670 × 860 before the restored 774 × 886), so pulses ran about 50 points off their lines, some of them over the list. Pulses run only while the window is seen (`WindowVisibility`: occlusion, miniaturize, app hidden), something moves, and Reduce Motion is off; otherwise there are no layers and no frames. `map-flows` gives "N moving", "paused" or "idle".
3. **The map draws less.** `MapLayer` (the pins, lines and camera) is `Equatable` on what it draws (pin and line ids and states, the fitted region within 0.01°), so a pass that only changes traffic numbers no longer makes MapKit lay out and draw again; the camera follows only when the region that fits the pins changes, not when the same pins come in another order.
4. **Audit (build 24, a real Mac, window open).** Rat.app's CPU was mostly VectorKit redrawing the map on every pass (9.6 % open, 3.2 % closed); point 3 removes that. The 500–600 MB footprint is MapKit's tile and label caches growing with camera moves and Graphics memory (~146 MB): it fell to ~375 MB with the window closed and settled near 414 MB reopened; Rat's own heap is a small part of it. Unbounded caches are bounded: `GeoService`'s city and ASN caches and `HostNames` start again past 16,384 addresses (`GeoService.cacheLimit`), and `uidCache` keeps live pids only (a reused pid could take a stale uid).
5. **Budgets (`PerformanceBudgetTests`, `DaemonPerformanceTests`).** A ledger pass of 2,000 sockets in 200 apps takes ~27 ms in Debug (budget 0.25 s of its 1.5 s); the map graph of 2,000 connections ~2 ms (budget 0.1 s); 130 passes with a fresh set of sockets each leave malloc flat (budget 15 MB). A pass leaves ~1.7 MB of autoreleased temporaries that go when it ends, so the test runs each pass as a job of its own, as the timer does: 130 passes in one job hold them all (+220 MB), which is not a leak. The helper's fast pass with 64 sockets takes 0.08 ms in Release (budget 1.5 ms of its 3 ms), a full scan 0.15 ms (budget 50 ms), and 6,000 passes with sockets coming and going leave its malloc flat (budget 2 MB).
6. **The helper's first second.** A process younger than a second has its path read on every pass so its exec is noticed. Its age counted from when the daemon first met it, so at the daemon's start, and again whenever the deny list changed (`verdictCache` is cleared), every process on the Mac was young: the first 1.2 s of passes took 2.6 s (a core flat out). The age is now the kernel's (`ConnectionSampler.startTime`, `kinfo_proc.p_starttime`, readable for any user's process): those passes take 35 ms. A process that really is new is followed exactly as before.
7. **A deny takes effect at once.** With nothing denied, the daemon sleeps 0.25 s between passes (`idleInterval`) and reads its files at most every 50 ms, so a deny made then waited up to a quarter second. Into a socket buffer that is not full yet (a rate-limited reader early in a download, or a stream through a local proxy), the server kept sending all that time: `verify-blocking.sh`'s mid-stream phases passed or failed depending on where in the sleep the deny landed. `FileWake` (RatEnforce) watches the folders of `denied-apps.txt`, `denied-ports.txt`, `deny-rules.json` and the repair file (Rat replaces them by renaming, which writes the folder) and the files themselves (written in place, they change only themselves; watched again after each folder change, since a replaced file is a new inode). A change ends the sleep, and `filesChanged` skips the 50 ms check, so the pass that follows reads the file: a deny written while idle is loaded in a few ms (27 ms in a Debug test, two passes: the atomic write's temporary file, then its rename). The sources are opened with `O_EVTONLY` and closed when re-armed (no descriptor kept per change); the timed sleep stays the fallback. The pass right after a deny-list change also reads no process start times before loading its ports (they come at the end of the pass: reading 938 of them first took 15 ms there).
