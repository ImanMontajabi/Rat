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

## 10. Revision 4 (v1.0.2): blocking a denied app by its sockets

Chasing the server addresses of a denied browser every 1.5 s cannot work: Chrome and Firefox rotate CDN addresses, fall back to IPv6 and move QUIC streams, so each new address downloads for a moment before it is blocked.

Deny now has three layers. All are loaded into the `com.apple/rat` pf anchor by the root daemon `rat-enforcerd` (a LaunchDaemon with `KeepAlive`, installed with the helper):

1. **Grouping.** Every helper process is attributed to its app: the outermost `.app` or `.AppBundle` in the path (Chrome Helper variants, Firefox `plugin-container`, `Steam Helper`, `steam_osx`, `ipcserver` all live inside their app), and system XPC services such as `com.apple.WebKit.Networking` follow `responsibility_get_pid_responsible_for_pid` to Safari. Only system services borrow their client's identity, so `curl` run from a Terminal stays `curl`.
2. **Ports.** Rat writes the apps that are denied outright (a whole-app Deny, no allow exceptions, or Silent Deny) to `denied-apps.txt`. The daemon reads the process list every 10 ms, reads the sockets of those processes every 50 ms (every 10 ms for the first 0.6 s of a new process) and blocks their local ports in both directions, TCP and UDP, IPv4 and IPv6, never on `lo0`. Ports stay blocked 5 s after the socket closes. Servers they reached have their pf states killed.
3. **Addresses.** `blocklist.txt` (servers seen while an app was denied) is a table that blocks everyone. Seen servers are blocked before a single packet.

pf cannot match a process, so the port layer reacts to a socket after it exists. A SYN may leave before the ports are loaded; the server's answer is dropped when it arrives, so a connection to a distant server fails, but one to a server less than a few milliseconds away can complete its handshake first. `scripts/verify-blocking.sh` (needs `sudo`) measures this with fresh `curl` processes, the hardest case, and checks the address layer for zero bytes. Closing the gap needs a Network Extension.
