use anyhow::{Context, Result, bail};
use netstat2::{AddressFamilyFlags, ProtocolFlags, ProtocolSocketInfo, get_sockets_info};
use rat_core::{BlockRule, Connection, Location, Snapshot};
use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
    process::Command,
    time::Instant,
};

// Resolve relative to the executable first: Explorer/shortcuts need not start in
// the app folder. Cargo binaries live in target/{debug,release}[/deps].
fn geo_path(
    explicit: Option<PathBuf>,
    executable: Option<&Path>,
    cwd: Option<&Path>,
) -> Option<PathBuf> {
    if explicit.is_some() {
        return explicit;
    }
    let beside_exe = executable.and_then(Path::parent);
    let mut roots = beside_exe.into_iter().collect::<Vec<_>>();
    if let Some(dir) = beside_exe {
        let build = if dir.file_name().is_some_and(|n| n == "deps") {
            dir.parent()
        } else {
            Some(dir)
        };
        if let Some(target) = build
            .and_then(Path::parent)
            .filter(|p| p.file_name().is_some_and(|n| n == "target"))
        {
            roots.extend(target.parent());
        }
    }
    roots.extend(cwd);
    roots
        .into_iter()
        .map(|root| root.join("geoip/dbip-city-lite.mmdb"))
        .find(|p| p.is_file())
}
use sysinfo::{Networks, System};

pub struct Monitor {
    system: System,
    networks: Networks,
    last: Instant,
    geo: Option<maxminddb::Reader<Vec<u8>>>,
    geo_error: Option<String>,
}

#[cfg(test)]
mod geo_tests {
    use super::*;

    #[test]
    fn discovers_database_for_cargo_and_portable_launches() {
        let root = std::env::temp_dir().join(format!("rat-geo-{}", std::process::id()));
        let repo = root.join("repo");
        let portable = root.join("portable");
        for base in [&repo, &portable] {
            std::fs::create_dir_all(base.join("geoip")).unwrap();
            std::fs::write(base.join("geoip/dbip-city-lite.mmdb"), b"fixture").unwrap();
        }
        for binary in [
            "target/debug/rat-desktop.exe",
            "target/release/rat-desktop.exe",
            "target/debug/deps/test.exe",
        ] {
            assert_eq!(
                geo_path(None, Some(&repo.join(binary)), Some(&root)),
                Some(repo.join("geoip/dbip-city-lite.mmdb"))
            );
        }
        assert_eq!(
            geo_path(None, Some(&portable.join("Rat.exe")), Some(&repo)),
            Some(portable.join("geoip/dbip-city-lite.mmdb"))
        );
        assert_eq!(
            geo_path(None, Some(&root.join("Rat.exe")), Some(&repo)),
            Some(repo.join("geoip/dbip-city-lite.mmdb"))
        );
        let explicit = root.join("custom.mmdb");
        assert_eq!(
            geo_path(
                Some(explicit.clone()),
                Some(&portable.join("Rat.exe")),
                Some(&repo)
            ),
            Some(explicit)
        );
        assert_eq!(
            geo_path(None, Some(&root.join("Rat.exe")), Some(&root)),
            None
        );
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    #[ignore = "requires the locally installed DB-IP City database"]
    fn installed_database_resolves_public_addresses_and_live_connections() {
        let mut monitor = Monitor::default();
        let reader = monitor.geo.as_ref().expect("GeoIP database should load");
        for ip in ["8.8.8.8", "1.1.1.1", "2001:4860:4860::8888"] {
            let city = reader
                .lookup::<maxminddb::geoip2::City>(ip.parse().unwrap())
                .unwrap()
                .unwrap();
            assert!(
                city.country.and_then(|c| c.names).is_some(),
                "{ip} has no country"
            );
            assert!(
                city.city.and_then(|c| c.names).is_some(),
                "{ip} has no city"
            );
            let location = city.location.unwrap();
            assert!(location.latitude.is_some() && location.longitude.is_some());
        }
        let snapshot = monitor.sample().unwrap();
        assert!(snapshot.geo_available);
        assert!(snapshot.geo_error.is_none());
        eprintln!(
            "Live TCP destinations: {}, located: {}",
            snapshot.connections.len(),
            snapshot
                .connections
                .iter()
                .filter(|c| c.location.is_some())
                .count()
        );
    }
}

impl Default for Monitor {
    fn default() -> Self {
        let explicit = std::env::var_os("RAT_GEOIP_DB").map(std::path::PathBuf::from);
        let executable = std::env::current_exe().ok();
        let cwd = std::env::current_dir().ok();
        let path = geo_path(explicit, executable.as_deref(), cwd.as_deref());
        let (geo, geo_error) = match path {
            Some(path) => match maxminddb::Reader::open_readfile(&path) {
                Ok(reader) => (Some(reader), None),
                Err(error) => (None, Some(format!("Cannot open GeoIP database {}: {error}", path.display()))),
            },
            None => (None, Some("GeoIP database missing. Place geoip/dbip-city-lite.mmdb beside Rat.exe or set RAT_GEOIP_DB to a City .mmdb file, then restart Rat.".into())),
        };
        Self {
            system: System::new_all(),
            networks: Networks::new_with_refreshed_list(),
            last: Instant::now(),
            geo,
            geo_error,
        }
    }
}

impl Monitor {
    pub fn sample(&mut self) -> Result<Snapshot> {
        self.system
            .refresh_processes(sysinfo::ProcessesToUpdate::All, true);
        self.networks.refresh(true);
        let seconds = self.last.elapsed().as_secs_f64().max(0.001);
        self.last = Instant::now();
        let mut snapshot = Snapshot {
            geo_available: self.geo.is_some(),
            geo_error: self.geo_error.clone(),
            ..Default::default()
        };
        for (_, network) in &self.networks {
            snapshot.received_per_sec += network.received() as f64 / seconds;
            snapshot.sent_per_sec += network.transmitted() as f64 / seconds;
        }
        let sockets = get_sockets_info(
            AddressFamilyFlags::IPV4 | AddressFamilyFlags::IPV6,
            ProtocolFlags::TCP,
        )
        .context("Cannot read system TCP connections")?;
        for socket in sockets {
            let ProtocolSocketInfo::Tcp(tcp) = socket.protocol_socket_info else {
                continue;
            };
            if tcp.remote_addr.is_unspecified() || tcp.remote_port == 0 {
                continue;
            }
            let pid = socket.associated_pids.first().copied().unwrap_or(0);
            let process = self
                .system
                .process(sysinfo::Pid::from_u32(pid))
                .map(|p| p.name().to_string_lossy().into_owned())
                .unwrap_or_else(|| format!("PID {pid}"));
            let location = self.geo.as_ref().and_then(|reader| {
                let city = reader
                    .lookup::<maxminddb::geoip2::City>(tcp.remote_addr)
                    .ok()??;
                let location = city.location?;
                let city_name = city
                    .city
                    .and_then(|c| c.names)
                    .and_then(|n| n.get("en").copied())
                    .map(str::to_string);
                let country = city
                    .country
                    .and_then(|c| c.names.and_then(|n| n.get("en").copied()).or(c.iso_code))
                    .map(str::to_string);
                let label = [city_name.as_deref(), country.as_deref()]
                    .into_iter()
                    .flatten()
                    .collect::<Vec<_>>()
                    .join(", ");
                Some(Location {
                    label: if label.is_empty() {
                        "Unknown location".into()
                    } else {
                        label
                    },
                    city: city_name,
                    country,
                    latitude: location.latitude?,
                    longitude: location.longitude?,
                })
            });
            snapshot.connections.push(Connection {
                process,
                pid,
                local: SocketAddr::new(tcp.local_addr, tcp.local_port),
                remote: SocketAddr::new(tcp.remote_addr, tcp.remote_port),
                state: format!("{:?}", tcp.state),
                location,
            });
        }
        snapshot
            .connections
            .sort_by(|a, b| (&a.process, a.pid, a.remote).cmp(&(&b.process, b.pid, b.remote)));
        Ok(snapshot)
    }
}

// Commands never pass through a shell. Addresses are parsed IpAddr values and
// the only rule identifiers accepted belong to this application.
fn hidden(command: &mut Command) -> &mut Command {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x08000000);
    }
    command
}

pub fn read_rules() -> Result<Vec<BlockRule>> {
    if !cfg!(windows) {
        bail!("Firewall control currently supports Windows only");
    }
    let output = hidden(Command::new("powershell.exe").args([
        "-NoProfile", "-NonInteractive", "-Command",
        "$ErrorActionPreference='Stop'; ConvertTo-Json -InputObject @(Get-NetFirewallRule -PolicyStore PersistentStore | Where-Object { $_.Name -like 'Rat.Rust.v1.*' -and $_.Enabled -eq 'True' -and $_.Action -eq 'Block' } | Select-Object -ExpandProperty Name) -Compress",
    ])).output().context("Cannot query Windows Defender Firewall")?;
    if !output.status.success() {
        bail!(
            "Firewall query failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    let raw = String::from_utf8_lossy(&output.stdout);
    if raw.trim().is_empty() {
        return Ok(vec![]);
    }
    let names: Vec<String> =
        serde_json::from_str(raw.trim()).context("Invalid firewall response")?;
    Ok(names
        .iter()
        .filter_map(|n| BlockRule::from_name(n))
        .collect())
}

pub fn set_block(rule: &BlockRule, blocked: bool) -> Result<()> {
    if !cfg!(windows) {
        bail!("Firewall control currently supports Windows only");
    }
    let name = rule.direction.rule_name(rule.ip);
    // The interpolated values are a fixed prefix, an enum and a parsed IpAddr.
    // Never interpolate raw user input or a process name into PowerShell.
    let script = if blocked {
        format!(
            "$ErrorActionPreference='Stop'; New-NetFirewallRule -PolicyStore PersistentStore -Name '{name}' -DisplayName '{name}' -Group 'Rat.Rust.v1' -Direction {} -Action Block -RemoteAddress '{}' -Profile Any -Enabled True | Out-Null",
            rule.direction.label(),
            rule.ip
        )
    } else {
        format!(
            "$ErrorActionPreference='Stop'; Remove-NetFirewallRule -PolicyStore PersistentStore -Name '{name}'"
        )
    };
    let mut cmd = Command::new("powershell.exe");
    cmd.args(["-NoProfile", "-NonInteractive", "-Command", &script]);
    let output = hidden(&mut cmd)
        .output()
        .context("Cannot start Windows firewall control")?;
    if !output.status.success() {
        let diagnostic = String::from_utf8_lossy(&output.stderr)
            .lines()
            .find(|line| !line.trim().is_empty())
            .unwrap_or("No details returned")
            .chars()
            .take(240)
            .collect::<String>();
        bail!("Windows rejected the firewall change. Run Rat as administrator. {diagnostic}");
    }
    Ok(())
}
