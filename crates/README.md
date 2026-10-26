<p align="center"><img src="../docs/icon.png" width="100" alt="Rat icon"></p>

# Rat for Windows

A native Rust network monitor built with GPUI Kit. See which applications connect to which server IPs, explore their approximate locations on a map, and manage inbound and outbound IP blocks through Windows Defender Firewall.

This Windows implementation accompanies the original [Swift/macOS Rat](https://github.com/ImanMontajabi/Rat). It is an early port with its own platform adapter, not full feature parity.

## Screenshot

![Rat for Windows showing Telegram connections to cities in Europe and Singapore, green connection curves and a statistics panel](../docs/screenshots/rat-windows-monitor.png)

The selected application's destinations appear on an interactive OpenStreetMap basemap. Green curves connect them to “This PC,” whose location is estimated offline from the Windows time zone. The upload/download cards and traffic chart show system-wide rates, even when an app is selected.

## Features

- Live TCP IPv4/IPv6 connections with process names, PIDs, local and remote addresses, ports and connection states.
- Expandable application list with search and sorting by name, recently observed connections or socket count.
- City and country markers from a local DB-IP GeoIP database; inspect the applications and server endpoints sharing a location.
- Mouse drag to pan, mouse wheel to zoom toward the pointer, and Fit to frame the displayed connections.
- Curved connection lines, selected-app highlighting, a frosted map-backed inspector and collapsible detail sections.
- Purple upload and blue download history, plus per-app socket-count mini charts.
- Inbound and outbound IP blocks, a searchable rules view and session display settings.
- Rat's icon embedded in the Windows executable, title bar and taskbar.

## Build and run

Requires Windows 10/11, the Rust MSVC toolchain, Visual Studio C++ Build Tools with a Windows SDK, and CMake. Run these commands from the repository root:

```powershell
# Recommended: download the local city database.
powershell -NoProfile -File scripts/fetch-geoip.ps1

# Run the app.
cargo run --locked -p rat-desktop

# Build a portable optimized package with GeoIP included.
powershell -NoProfile -File scripts/package-windows.ps1 -IncludeGeoIP
```

Launch `dist/Rat/Rat.exe` and keep its adjacent `geoip` folder. Ordinary monitoring works without elevation; creating or removing firewall blocks requires running Rat as administrator.

## Controls

| Action | Control |
| --- | --- |
| Show an application's destinations | Select its name in the left pane |
| Inspect server endpoints | Expand the application row |
| Explore a city's connections | Click its map marker |
| Move around the map | Left-drag |
| Zoom at the pointer | Mouse wheel |
| Frame visible connections and the PC marker | Fit |
| Change charts, translucency, routes or animation | Settings → Monitor |

## Scope and privacy

IP blocks cover **all applications, protocols and ports** for the chosen remote IP and direction, and persist until removed. They are not app-specific rules. Enforcement depends on Windows Defender Firewall; live packet blocking has not been validated in this development session.

GeoIP lookups stay on the PC. Online map tiles are requested from OpenStreetMap and cached locally; those requests expose the client's public IP and requested map regions, but do not include destination IPs or process names. Map attribution remains visible in the app and screenshot: © OpenStreetMap contributors; GeoIP by DB-IP, CC BY 4.0.

The PC marker is a representative time-zone city, not GPS or a VPN exit location. Curves illustrate connections, not actual packet routes. TCP snapshots can miss short-lived connections; UDP peers, per-app bandwidth, alerts, profiles and automatic updates are not implemented.

See [the detailed Windows documentation](../docs/RUST_REWRITE.md) for architecture, firewall behavior, validation and third-party credits. Rat uses the repository's [MIT license](../LICENSE).
