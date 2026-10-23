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

Open `dist/Rat/Rat.exe`. Keep the adjacent `geoip` directory to retain the offline map.
Without the database, connection inspection and firewall controls still work.
Alternatively set `RAT_GEOIP_DB` to an existing City `.mmdb` database before launch.
An explicit invalid path produces a visible diagnostic. Database changes require restarting Rat.

## Features

- Live system TCP connection table: IPv4/IPv6, process name, PID, local/remote endpoints, TCP state.
- Search by application, address, PID, state or resolved location, with virtualized rows and keyboard-accessible selection buttons.
- Offline world atlas with a centered 2:1 projection that preserves its proportions at any window size; panel height adapts to the available window space.
- Hover a point for its city, country and connected app names. Click it to browse every matching process and server IP/port at that location.
- Select a connection to highlight its map location. “All apps at this location” opens that location’s process list; “Show this app on map” filters both map and table. Clear search restores all apps.
- The atlas header’s locations button opens a keyboard-accessible location browser. Multiple processes and server IPs sharing coordinates stay grouped and remain individually inspectable.
- Download/upload interface rates and a rolling history of 60 samples. Pause freezes the displayed monitoring snapshot.
- Connection inspector with separate inbound/outbound IP blocks.
- Add arbitrary IPv4/IPv6 addresses, inspect Rat rules, remove them, and filter the monitor to IPs with Rat blocks.
- Persistent Windows Defender Firewall rules; changes and external rule edits are queried from Windows (refresh every 15 seconds or manually).
- Independent monitoring and firewall threads keep firewall commands off the UI thread and sampling loop.

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
Map geometry, pins and pointer hit testing use the same aspect-preserving viewport. Unused space is centered around the world so wide panels do not stretch continents.

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
and seven automated tests passed. A native window was inspected with live connections, real offline GeoIP markers and city/country labels.
The elevated lifecycle test was not run because the session was not an administrator; live firewall enforcement remains unverified here.

The suggested [GPUI CE](https://gpui-ce.github.io/) project was reviewed. It is an alternative GPUI framework;
this app retains GPUI Kit's pinned runtime and styled components rather than mixing two runtime type systems.

## Credits

Rat is MIT-licensed; see the repository LICENSE. GPUI Kit and GPUI are Apache-2.0.
The bundled `land.geojson` is Natural Earth's public-domain 1:110m land geometry,
from [natural-earth-vector](https://github.com/nvkelso/natural-earth-vector/blob/master/geojson/ne_110m_land.geojson).
Optional geolocation is by [DB-IP](https://db-ip.com), using the City Lite database under
[CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). Attribution appears in the map and this document.
Downloading the database contacts DB-IP; subsequent lookups remain on the device.
