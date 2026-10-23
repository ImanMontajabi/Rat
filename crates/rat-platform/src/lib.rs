use anyhow::{Context, Result, bail};
use netstat2::{AddressFamilyFlags, ProtocolFlags, ProtocolSocketInfo, get_sockets_info};
use rat_core::{BlockRule, Connection, Location, Snapshot};
use std::{net::SocketAddr, path::Path, process::Command, time::Instant};
use sysinfo::{Networks, System};

pub struct Monitor {
    system: System,
    networks: Networks,
    last: Instant,
    geo: Option<maxminddb::Reader<Vec<u8>>>,
    geo_error: Option<String>,
}

impl Default for Monitor {
    fn default() -> Self {
        let explicit = std::env::var_os("RAT_GEOIP_DB").map(std::path::PathBuf::from);
        let path = explicit.or_else(|| {
            let local = Path::new("geoip/dbip-city-lite.mmdb").to_path_buf();
            if local.exists() {
                return Some(local);
            }
            std::env::current_exe()
                .ok()
                .and_then(|exe| exe.parent().map(|p| p.join("geoip/dbip-city-lite.mmdb")))
                .filter(|p| p.exists())
        });
        let loaded = path.map(maxminddb::Reader::open_readfile);
        let geo_error = loaded
            .as_ref()
            .and_then(|r| r.as_ref().err())
            .map(|e| format!("Cannot open GeoIP database: {e}"));
        let geo = loaded.and_then(Result::ok);
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
