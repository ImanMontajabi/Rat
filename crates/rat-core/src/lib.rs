use serde::{Deserialize, Serialize};
pub mod map;
use std::{
    collections::{BTreeMap, BTreeSet},
    net::{IpAddr, SocketAddr},
};

#[derive(Clone, Debug)]
pub struct Connection {
    pub process: String,
    pub pid: u32,
    pub local: SocketAddr,
    pub remote: SocketAddr,
    pub state: String,
    pub location: Option<Location>,
}

impl Connection {
    pub fn key(&self) -> String {
        format!("{}:{}>{}", self.pid, self.local, self.remote)
    }
    pub fn matches(&self, query: &str) -> bool {
        let query = query.to_lowercase();
        format!(
            "{} {} {} {} {}",
            self.process,
            self.pid,
            self.remote,
            self.state,
            self.location
                .as_ref()
                .map(|l| l.label.as_str())
                .unwrap_or("")
        )
        .to_lowercase()
        .contains(&query)
    }
}

#[derive(Clone, Debug)]
pub struct Location {
    pub label: String,
    pub city: Option<String>,
    pub country: Option<String>,
    pub latitude: f64,
    pub longitude: f64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct LocationKey(pub i32, pub i32);

impl Location {
    pub fn key(&self) -> LocationKey {
        LocationKey(
            (self.longitude * 10_000.).round() as i32,
            (self.latitude * 10_000.).round() as i32,
        )
    }
}

#[derive(Clone, Debug)]
pub struct Destination {
    pub location: Location,
    pub connections: Vec<Connection>,
}

impl Destination {
    pub fn app_count(&self) -> usize {
        self.connections
            .iter()
            .map(|c| (&c.process, c.pid))
            .collect::<BTreeSet<_>>()
            .len()
    }
    pub fn server_count(&self) -> usize {
        self.connections
            .iter()
            .map(|c| c.remote.ip())
            .collect::<BTreeSet<_>>()
            .len()
    }
    pub fn summary(&self) -> String {
        let apps = self
            .connections
            .iter()
            .map(|c| c.process.as_str())
            .collect::<BTreeSet<_>>();
        let mut names = apps.iter().take(3).copied().collect::<Vec<_>>().join(", ");
        if apps.len() > 3 {
            names.push_str(&format!(" +{} more", apps.len() - 3));
        }
        format!(
            "{} · {} · {} server IPs",
            self.location.label,
            names,
            self.server_count()
        )
    }
}

pub fn destinations(connections: &[Connection]) -> Vec<Destination> {
    let mut groups: BTreeMap<LocationKey, Destination> = BTreeMap::new();
    for connection in connections {
        if let Some(location) = &connection.location {
            groups
                .entry(location.key())
                .or_insert_with(|| Destination {
                    location: location.clone(),
                    connections: vec![],
                })
                .connections
                .push(connection.clone());
        }
    }
    let mut result: Vec<_> = groups.into_values().collect();
    result.sort_by(|a, b| {
        a.location
            .label
            .cmp(&b.location.label)
            .then(a.location.key().cmp(&b.location.key()))
    });
    result
}

/// Center a 2:1 equirectangular world inside a viewport without stretching or cropping.
#[derive(Clone, Copy, Debug)]
pub struct MapViewport {
    pub x: f32,
    pub y: f32,
    pub width: f32,
    pub height: f32,
}
impl MapViewport {
    pub fn camera(mut self, zoom: f32, pan: (f32, f32)) -> Self {
        let old_width = self.width;
        let old_height = self.height;
        self.width *= zoom;
        self.height *= zoom;
        self.x += (old_width - self.width) / 2. + pan.0 * old_width;
        self.y += (old_height - self.height) / 2. + pan.1 * old_height;
        self
    }
    pub fn fit(width: f32, height: f32) -> Self {
        let world_width = width.max(0.).min(height.max(0.) * 2.);
        let world_height = world_width / 2.;
        Self {
            x: (width - world_width) / 2.,
            y: (height - world_height) / 2.,
            width: world_width,
            height: world_height,
        }
    }
    pub fn point(self, longitude: f64, latitude: f64) -> (f32, f32) {
        let (x, y) = project(longitude, latitude);
        (self.x + self.width * x, self.y + self.height * y)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Direction {
    Inbound,
    Outbound,
}

impl Direction {
    pub fn label(self) -> &'static str {
        match self {
            Self::Inbound => "Inbound",
            Self::Outbound => "Outbound",
        }
    }
    pub fn rule_name(self, ip: IpAddr) -> String {
        format!("Rat.Rust.v1.{}.{}", self.label(), ip)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockRule {
    pub ip: IpAddr,
    pub direction: Direction,
}

impl BlockRule {
    pub fn from_name(name: &str) -> Option<Self> {
        let rest = name.strip_prefix("Rat.Rust.v1.")?;
        let (direction, ip) = rest.split_once('.')?;
        Some(Self {
            ip: ip.parse().ok()?,
            direction: match direction {
                "Inbound" => Direction::Inbound,
                "Outbound" => Direction::Outbound,
                _ => return None,
            },
        })
    }
}

#[derive(Clone, Default)]
pub struct Snapshot {
    pub connections: Vec<Connection>,
    pub received_per_sec: f64,
    pub sent_per_sec: f64,
    pub geo_available: bool,
    pub geo_error: Option<String>,
}

pub fn project(longitude: f64, latitude: f64) -> (f32, f32) {
    (
        ((longitude + 180.) / 360.) as f32,
        ((90. - latitude) / 180.) as f32,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn owned_rule_names_roundtrip_v4_and_v6() {
        for ip in ["203.0.113.8", "2001:db8::1"] {
            for direction in [Direction::Inbound, Direction::Outbound] {
                let rule = BlockRule {
                    ip: ip.parse().unwrap(),
                    direction,
                };
                assert_eq!(
                    BlockRule::from_name(&direction.rule_name(rule.ip)),
                    Some(rule)
                );
            }
        }
        for invalid in [
            "Other.Inbound.1.1.1.1",
            "Rat.Rust.v1.Any.1.1.1.1",
            "Rat.Rust.v1.Inbound.any",
            "Rat.Rust.v1.Outbound.1.1.1.1;evil",
        ] {
            assert!(BlockRule::from_name(invalid).is_none());
        }
    }
    #[test]
    fn map_projection_has_known_bounds() {
        assert_eq!(project(-180., 90.), (0., 0.));
        assert_eq!(project(180., -90.), (1., 1.));
        assert_eq!(project(0., 0.), (0.5, 0.5));
    }
    #[test]
    fn map_keeps_equal_degree_scales_in_wide_and_tall_windows() {
        for (w, h) in [(1200., 190.), (400., 600.), (700., 350.)] {
            let fit = MapViewport::fit(w, h);
            assert_eq!(fit.width, fit.height * 2.);
            assert!(fit.x >= 0. && fit.y >= 0.);
            assert!(fit.x + fit.width <= w && fit.y + fit.height <= h);
            let center = fit.point(0., 0.);
            assert_eq!(center, (w / 2., h / 2.));
            let east = fit.point(10., 0.);
            let south = fit.point(0., -10.);
            assert!(((east.0 - center.0) - (south.1 - center.1)).abs() < 0.001);
        }
    }
    #[test]
    fn shared_city_keeps_every_process_and_server() {
        let location = Location {
            label: "Amsterdam, Netherlands".into(),
            city: Some("Amsterdam".into()),
            country: Some("Netherlands".into()),
            latitude: 52.37,
            longitude: 4.9,
        };
        let make = |pid, process: &str, remote: &str| Connection {
            pid,
            process: process.into(),
            remote: remote.parse().unwrap(),
            local: "127.0.0.1:1234".parse().unwrap(),
            state: "Established".into(),
            location: Some(location.clone()),
        };
        let mut connections = vec![
            make(1, "Browser", "203.0.113.1:443"),
            make(1, "Browser", "203.0.113.1:80"),
            make(2, "Chat", "203.0.113.2:443"),
        ];
        let mut unresolved = make(3, "Unknown", "192.0.2.1:443");
        unresolved.location = None;
        connections.push(unresolved);
        let groups = destinations(&connections);
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].connections.len(), 3);
        assert_eq!(groups[0].app_count(), 2);
        assert_eq!(groups[0].server_count(), 2);
        assert!(connections[2].matches("netherlands"));
    }
}
