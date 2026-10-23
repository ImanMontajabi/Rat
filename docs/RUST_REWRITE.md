# Rat for Windows — Rust rewrite

A native network monitor built with Rust and [GPUI Kit 0.8.0](https://gpui-kit.com/).
The original Swift/macOS implementation remains available in `App/` and `RatFilter/`.

## Run

Requirements: Windows 10/11, Rust MSVC toolchain (Rust 1.92+), Visual Studio C++ Build Tools with a Windows SDK, and CMake.
The lockfile records the dependency versions used for this rewrite.

From the repository root:

```powershell
# Optional, recommended: download the offline city database (~127 MB expanded).
powershell -NoProfile -File scripts/fetch-geoip.ps1
cargo run --locked -p rat-desktop
```

Run the executable as administrator to create or remove IP blocks. Ordinary monitoring needs no elevation.
Rat never elevates silently. The application reports access-denied errors in its status bar.

For a portable optimized build:

```powershell
powershell -NoProfile -File scripts/package-windows.ps1 -IncludeGeoIP
```

Open `dist/Rat/Rat.exe`. Keep the adjacent `geoip` directory for local destination geolocation.
The executable embeds Rat's existing artwork as a multi-resolution Windows icon (16–256 px), used by Explorer, the title bar and the taskbar.
Without the database, connection inspection and firewall controls still work.
Alternatively set `RAT_GEOIP_DB` to an existing City `.mmdb` database before launch.
An explicit invalid path produces a visible diagnostic. Database changes require restarting Rat.

## Features

- Live system TCP connection table: IPv4/IPv6, process name, PID, local/remote endpoints, TCP state.
- Three-pane monitor inspired by the supplied Swift app references: searchable expandable applications and traffic on the left, a large map in the center, and Summary / connection inspector on the right.
- Map-backed frosted inspector with collapsible Summary, Process, Connection Details, Geographic Information and IP Rules sections. The blur is generated from the map tiles behind the panel on a worker; it is an in-app material, not desktop transparency.
- Sort applications by Name, Recent (newly observed connections), or Sockets (current count). Reordering uses a 220 ms eased transition with stable application identities and respects reduced motion. Settings → Monitor can disable translucency and row animation.
- Search by application, address, PID, state or resolved location; expand an app to inspect its unique process/remote endpoints. App selection filters the map without losing the full application list.
- Curved connections from a laptop-shaped “This PC” marker to destination cities; selecting an app highlights its routes. The origin is the representative city of the Windows time zone (an offline estimate, matching Swift), not a measured physical location. The marker and Monitor settings say “approximate”; unsupported zones hide routes. Settings → Monitor can disable routes. Fit includes the origin, and curves illustrate connections rather than packet paths.
- Online OpenStreetMap basemap with Web Mercator projection, roads and place names. Destination coordinates still come from the local GeoIP database.
- Left-drag to pan. Scroll over the map to zoom toward the pointer. Small pointer movement remains a marker click; dragging does not accidentally select a marker. Keyboard-accessible pan/zoom buttons remain available.
- Fit frames matching destinations with padding and a minimum regional span, including points across the date line. Initial data and app/search changes fit once; ongoing monitoring does not undo manual navigation.
- Hover a point for its city, country and connected app names. Click it to browse every matching process and server IP/port at that location.
- Select a connection to highlight its map location. “All apps at this location” opens that location’s process list; “Show this app on map” filters both map and table. Clear search restores all apps.
- The map header’s locations button opens a keyboard-accessible location browser. Multiple processes and server IPs sharing coordinates stay grouped and remain individually inspectable.
- Purple upload / blue download bars with a rolling history of 60 system-wide samples. Application mini charts show TCP socket counts for the most recent 30 samples, not per-app bandwidth. Pause freezes the displayed monitoring snapshot.
- Connection inspector with separate inbound/outbound IP blocks.
- Add arbitrary IPv4/IPv6 addresses, inspect Rat rules, remove them, and filter the monitor to IPs with Rat blocks.
- Persistent Windows Defender Firewall rules; changes and external rule edits are queried from Windows (refresh every 15 seconds or manually).
- Independent monitoring and firewall threads keep firewall commands off the UI thread and sampling loop.
- Rules use a searchable striped table with process scope, description and active status. Settings have General, Monitor, Security and About tabs; display choices currently apply to the session.

## Firewall behavior

Blocks cover **all applications, protocols and ports** for the specified remote IP and direction, across all profiles.
They survive closing Rat and rebooting Windows. Remove the rule in Rat to unblock it; removing a Rat block does not override other Windows or organization policies.
The table's “No IP block” means no enabled Rat-owned IP rule was found; it is not a verdict on the rest of the system's firewall policy.
Firewall enforcement requires Windows Defender Firewall and applicable profiles to be enabled. Rat does not enable or disable those system settings.

Rule names use the namespace `Rat.Rust.v1.<Inbound|Outbound>.<IP>` in Windows' persistent policy store.
Only this namespace is queried or removed. IP input is parsed to `IpAddr` before constructing any command;
raw input, process names and executable paths never enter PowerShell code. The subprocess is hidden and noninteractive.
The app changes its displayed rule state only after querying Windows, and exposes failures rather than displaying an optimistic success.

## Current scope

This Windows version implements the requested destination visualization and directional IP controls.
It does not port every feature of the original macOS application: profiles, rule groups, app-signature rules,
connection alerts, menu-bar controls and automatic updates remain future work.
TCP snapshots can miss short-lived connections and do not identify UDP peers or infer connection initiation direction.
Byte rates are system interface totals, not per-app or per-connection measurements. VPN/virtual interfaces can double-count traffic.
Geolocation is approximate, and private/unresolved addresses appear in the table without fabricated map pins.
There is no packet inspection, DNS interception, online GeoIP lookup or user traffic upload.
The UI is designed for desktop windows with a minimum client size of 1180 × 760.
Tiles, pins and pointer hit testing share the same Web Mercator camera. The online basemap uses OpenStreetMap rather than Apple Maps imagery. Bundled country geometry is a fallback while tiles are loading or unavailable. The time-zone origin can be far from the PC, especially in geographically large zones; it does not locate VPN exit nodes.

## Swift map comparison and online map requests

The Swift `App/Views/MapPane.swift` imports MapKit. SwiftUI `Map` supplies Apple Maps imagery and gestures; Rat adds city `Annotation`s, quadratic `MapPolyline` arcs and `MKCoordinateRegion` fitting. `.standard(elevation: .realistic, emphasis: .muted)` selects the basemap style. Its `This Mac` origin is an estimate from the time-zone locator in `App/Model/Geo.swift`.

The Windows UI stays native GPUI. It fetches only currently visible OpenStreetMap PNG tiles over HTTPS, with two background workers and an identifying Rat User-Agent. No bulk download or prefetch is performed. Tiles are cached in `%LOCALAPPDATA%\RatRust\map-tiles\openstreetmap` for at least seven days; stale entries use ETag / Last-Modified conditional requests when those headers are available. In-memory tile images are bounded, failed downloads back off for a minute, and removed images are released from the GPU atlas.

OpenStreetMap sees the public client IP and tile coordinates/regions requested. Destination IPs, process names and packet contents are not included in map requests. GeoIP remains local. The map includes a visible OpenStreetMap attribution link. See the [tile usage policy](https://operations.osmfoundation.org/policies/tiles/) and [copyright page](https://www.openstreetmap.org/copyright).

Pre-redesign restore point: commit `e7a35c2`, pushed to `origin/main` before the Swift-style layout changes.

## Structure

| Crate | Responsibility |
| --- | --- |
| `rat-core` | Connections, directional rule identity, filtering and map projection |
| `rat-platform` | Native socket snapshots, process ownership, interface rates, MMDB lookup and Windows firewall adapter |
| `rat-desktop` | GPUI Kit UI, worker channels, table, inspector, map and activity graph |

## Validation

```powershell
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

The Windows integration test opens a real loopback connection and verifies its endpoints and owning PID in the system snapshot.
Rule discovery is read-only. The rule lifecycle test is opt-in and requires an elevated terminal:

```powershell
cargo test -p rat-platform --test windows elevated_firewall_rule_lifecycle -- --ignored --exact
```

It creates and removes inbound/outbound rules for the reserved documentation address `192.0.2.254`, refusing to touch an existing rule for that address.
It checks installation/removal, not packet delivery or organization policy precedence.

Development validation in this workspace: Windows debug and optimized portable release builds, formatting, Clippy with warnings denied,
and fifteen automated tests passed. A native window was inspected with live OpenStreetMap tiles, a frosted inspector, application sorting, locally resolved destination markers and city/country labels. Camera tests cover pointer-anchored zoom, marker alignment, date-line fitting and visible tile bounds. Additional tests cover sorting ties, interrupted reorder transitions, blurred tile wrapping, offline origin lookup and curve geometry across the date line.
The elevated lifecycle test was not run because the session was not an administrator; live firewall enforcement remains unverified here.

The suggested [GPUI CE](https://gpui-ce.github.io/) project was reviewed. It is an alternative GPUI framework;
this app retains GPUI Kit's pinned runtime and styled components rather than mixing two runtime type systems.

## Credits

Rat is MIT-licensed; see the repository LICENSE. GPUI Kit and GPUI are Apache-2.0.
The map uses Natural Earth's public-domain 1:110m country geometry in `countries.geojson`,
from [natural-earth-vector](https://github.com/nvkelso/natural-earth-vector/blob/master/geojson/ne_110m_admin_0_countries.geojson).
The earlier `land.geojson` outline is retained as a source asset for the previous layout.
Optional geolocation is by [DB-IP](https://db-ip.com), using the City Lite database under
[CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). Attribution appears in the map and this document.
Downloading the database contacts DB-IP; subsequent lookups remain on the device.

Time-zone origin data combines the IANA [zone.tab](https://github.com/eggert/tz/blob/main/zone.tab) representative coordinates (public domain) and Unicode CLDR [Windows mappings](https://github.com/unicode-org/cldr/blob/main/common/supplemental/windowsZones.xml). See `crates/rat-desktop/UNICODE-LICENSE.txt` (also included in the portable package). The bundled table covers 127 Windows time-zone identifiers; no geolocation request leaves the PC.
