//! Offline approximate origin, following Swift's time-zone representative city.
use std::process::Command;

#[derive(Clone, Debug)]
pub struct Origin {
    pub latitude: f64,
    pub longitude: f64,
    pub city: String,
}

pub fn locate() -> Option<Origin> {
    let mut command = Command::new("powershell.exe");
    command.args([
        "-NoProfile",
        "-NonInteractive",
        "-Command",
        "[System.TimeZoneInfo]::Local.Id",
    ]);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x08000000);
    }
    let output = command.output().ok()?;
    if !output.status.success() {
        return None;
    }
    from_zone(String::from_utf8_lossy(&output.stdout).trim())
}

fn from_zone(id: &str) -> Option<Origin> {
    let zones: serde_json::Value =
        serde_json::from_str(include_str!("../timezone-origins.json")).ok()?;
    let entry = &zones[id];
    Some(Origin {
        latitude: entry[0].as_f64()?,
        longitude: entry[1].as_f64()?,
        city: entry[2].as_str()?.into(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn timezone_origin_is_offline_and_unknown_is_not_fabricated() {
        let origin = from_zone("Iran Standard Time").unwrap();
        assert_eq!(origin.city, "Tehran");
        assert!((origin.latitude - 35.6667).abs() < 0.01);
        assert!((origin.longitude - 51.4333).abs() < 0.01);
        assert!(from_zone("Unknown time zone").is_none());
    }
}
