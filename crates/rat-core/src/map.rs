//! Web Mercator camera shared by tile placement, markers and pointer gestures.
#[derive(Clone, Copy, Debug)]
pub struct Camera {
    pub width: f32,
    pub height: f32,
    pub zoom: f32,
    pub pan: (f32, f32),
}
impl Camera {
    pub fn base(self) -> f32 {
        self.width.min(self.height).max(1.)
    }
    pub fn world(self) -> f32 {
        self.base() * self.zoom
    }
    pub fn origin(self) -> (f32, f32) {
        (
            (self.width - self.world()) / 2. + self.pan.0 * self.base(),
            (self.height - self.world()) / 2. + self.pan.1 * self.base(),
        )
    }
    pub fn point(self, longitude: f64, latitude: f64) -> (f32, f32) {
        let (x, y) = mercator(longitude, latitude);
        let (left, top) = self.origin();
        let x = left + x * self.world();
        (
            x + ((self.width / 2. - x) / self.world()).round() * self.world(),
            top + y * self.world(),
        )
    }
    pub fn zoom_at(self, factor: f32, anchor: (f32, f32)) -> Self {
        let zoom = (self.zoom * factor).clamp(0.75, 4096.);
        let (left, top) = self.origin();
        let scale = zoom / self.zoom;
        let new_left = anchor.0 - (anchor.0 - left) * scale;
        let new_top = anchor.1 - (anchor.1 - top) * scale;
        let size = self.base() * zoom;
        Self {
            zoom,
            pan: (
                (new_left - (self.width - size) / 2.) / self.base(),
                (new_top - (self.height - size) / 2.) / self.base(),
            ),
            ..self
        }
    }
    pub fn fitted(self, points: &[(f64, f64)]) -> Self {
        if points.is_empty() {
            return Self {
                zoom: 1.,
                pan: (0., 0.),
                ..self
            };
        }
        let mut xs: Vec<_> = points
            .iter()
            .map(|&(lon, lat)| mercator(lon, lat).0)
            .collect();
        xs.sort_by(f32::total_cmp);
        // Cut the longitude circle at its largest empty gap, so Fiji/Samoa fit across the dateline.
        let (gap_index, _) = xs
            .iter()
            .enumerate()
            .map(|(i, &x)| {
                (
                    i,
                    if i + 1 < xs.len() {
                        xs[i + 1] - x
                    } else {
                        xs[0] + 1. - x
                    },
                )
            })
            .max_by(|a, b| a.1.total_cmp(&b.1))
            .unwrap();
        let start = xs[(gap_index + 1) % xs.len()];
        let end = xs
            .iter()
            .map(|&x| if x < start { x + 1. } else { x })
            .fold(start, f32::max);
        let ys: Vec<_> = points
            .iter()
            .map(|&(lon, lat)| mercator(lon, lat).1)
            .collect();
        let low = ys.iter().copied().fold(1., f32::min);
        let high = ys.iter().copied().fold(0., f32::max);
        let size = ((self.width - 80.).max(80.) / (end - start).max(15. / 360.))
            .min((self.height - 80.).max(80.) / (high - low).max(15. / 360.));
        let zoom = (size / self.base()).clamp(0.75, 4096.);
        let world = self.base() * zoom;
        Self {
            zoom,
            pan: (
                (world * (0.5 - (start + end) / 2.)) / self.base(),
                (world * (0.5 - (low + high) / 2.)) / self.base(),
            ),
            ..self
        }
    }
}
pub fn mercator(longitude: f64, latitude: f64) -> (f32, f32) {
    let lat = latitude.clamp(-85.05112878, 85.05112878).to_radians();
    (
        ((longitude + 180.) / 360.) as f32,
        ((1. - lat.tan().asinh() / std::f64::consts::PI) / 2.) as f32,
    )
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct TileKey {
    pub z: u8,
    pub x: u32,
    pub y: u32,
}
pub struct Tile {
    pub key: TileKey,
    pub x: f32,
    pub y: f32,
    pub size: f32,
}
pub fn visible_tiles(camera: Camera) -> Vec<Tile> {
    tiles_in_region(camera, (0., 0., camera.width, camera.height))
}
pub fn tiles_in_region(camera: Camera, region: (f32, f32, f32, f32)) -> Vec<Tile> {
    let z = (camera.world() / 256.).log2().round().clamp(0., 18.) as u8;
    let n = 1i32 << z;
    let size = camera.world() / n as f32;
    let (left, top) = camera.origin();
    let start_x = ((region.0 - left) / size).floor() as i32;
    let end_x = ((region.0 + region.2 - left) / size).ceil() as i32;
    let start_y = (((region.1 - top) / size).floor() as i32).max(0);
    let end_y = (((region.1 + region.3 - top) / size).ceil() as i32).min(n);
    let mut tiles = vec![];
    for y in start_y..end_y {
        for x in start_x..end_x {
            tiles.push(Tile {
                key: TileKey {
                    z,
                    x: x.rem_euclid(n) as u32,
                    y: y as u32,
                },
                x: left + x as f32 * size,
                y: top + y as f32 * size,
                size,
            });
        }
    }
    tiles.sort_by(|a, b| {
        ((a.x + size / 2. - camera.width / 2.).powi(2)
            + (a.y + size / 2. - camera.height / 2.).powi(2))
        .total_cmp(
            &((b.x + size / 2. - camera.width / 2.).powi(2)
                + (b.y + size / 2. - camera.height / 2.).powi(2)),
        )
    });
    tiles
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn zoom_retains_geography_under_mouse() {
        let c = Camera {
            width: 800.,
            height: 600.,
            zoom: 3.,
            pan: (0.2, -0.1),
        };
        let p = c.point(10., 35.);
        let next = c.zoom_at(1.8, p);
        let q = next.point(10., 35.);
        assert!((p.0 - q.0).abs() < 0.01 && (p.1 - q.1).abs() < 0.01);
    }
    #[test]
    fn fit_handles_dateline_and_single_city() {
        let c = Camera {
            width: 800.,
            height: 600.,
            zoom: 1.,
            pan: (0., 0.),
        };
        let f = c.fitted(&[(179., 10.), (-179., 12.)]);
        for (lon, lat) in [(179., 10.), (-179., 12.)] {
            let p = f.point(lon, lat);
            assert!(p.0 > 0. && p.0 < 800. && p.1 > 0. && p.1 < 600.);
        }
        assert!(f.zoom > 3.);
        let single = c.fitted(&[(0., 0.)]);
        assert!(single.zoom < 30.);
    }
    #[test]
    fn tiles_are_visible_wrapped_and_bounded() {
        let c = Camera {
            width: 900.,
            height: 600.,
            zoom: 2.,
            pan: (2., 0.),
        };
        let tiles = visible_tiles(c);
        assert!(!tiles.is_empty() && tiles.len() < 40);
        for tile in tiles {
            assert!(tile.key.x < (1 << tile.key.z) && tile.key.y < (1 << tile.key.z));
            assert!(
                tile.x < 900.
                    && tile.x + tile.size > 0.
                    && tile.y < 600.
                    && tile.y + tile.size > 0.
            );
        }
    }
}
