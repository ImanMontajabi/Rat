use gpui_kit::*;
use rat_core::{Destination, LocationKey, MapViewport, project};
use std::{cell::Cell, rc::Rc, sync::OnceLock};
type Rings = Vec<Vec<(f32, f32)>>;
fn land() -> &'static Rings {
    static LAND: OnceLock<Rings> = OnceLock::new();
    LAND.get_or_init(|| {
        let json: serde_json::Value =
            serde_json::from_str(include_str!("../land.geojson")).expect("bundled map");
        let mut rings = vec![];
        for feature in json["features"].as_array().expect("map features") {
            let geometry = &feature["geometry"];
            let Some(coordinates) = geometry["coordinates"].as_array() else {
                continue;
            };
            let polygons = if geometry["type"] == "Polygon" {
                vec![&geometry["coordinates"]]
            } else {
                coordinates.iter().collect()
            };
            for polygon in polygons {
                let Some(ring) = polygon[0].as_array() else {
                    continue;
                };
                rings.push(
                    ring.iter()
                        .filter_map(|p| Some(project(p[0].as_f64()?, p[1].as_f64()?)))
                        .collect(),
                );
            }
        }
        rings
    })
}
pub fn map(
    destinations: Vec<Destination>,
    selected: Option<LocationKey>,
    hovered: Option<LocationKey>,
    on_select: impl Fn(&LocationKey, &mut Window, &mut App) + 'static,
    on_hover: impl Fn(&Option<LocationKey>, &mut Window, &mut App) + 'static,
) -> impl IntoElement {
    let destinations = Rc::new(destinations);
    let hit_bounds = Rc::new(Cell::new(None::<Bounds<Pixels>>));
    let paint_bounds = hit_bounds.clone();
    let click_bounds = hit_bounds.clone();
    let click_destinations = destinations.clone();
    let hover_destinations = destinations.clone();
    let hover_handler = Rc::new(on_hover);
    let exit_handler = hover_handler.clone();
    let drawing = canvas(
        move |bounds, _, _| {
            paint_bounds.set(Some(bounds));
        },
        move |bounds, _, window, _| {
            let fit = MapViewport::fit(f32::from(bounds.size.width), f32::from(bounds.size.height));
            let at = |x: f32, y: f32| {
                point(
                    bounds.origin.x + px(fit.x + fit.width * x),
                    bounds.origin.y + px(fit.y + fit.height * y),
                )
            };
            let mut grid = PathBuilder::stroke(px(0.5));
            for x in 1..12 {
                grid.move_to(at(x as f32 / 12., 0.));
                grid.line_to(at(x as f32 / 12., 1.));
            }
            for y in 1..6 {
                grid.move_to(at(0., y as f32 / 6.));
                grid.line_to(at(1., y as f32 / 6.));
            }
            if let Ok(path) = grid.build() {
                window.paint_path(path, rgb(0x223044));
            }
            for ring in land() {
                let mut path = PathBuilder::fill();
                for (i, &(x, y)) in ring.iter().enumerate() {
                    if i == 0 {
                        path.move_to(at(x, y));
                    } else {
                        path.line_to(at(x, y));
                    }
                }
                path.close();
                if let Ok(path) = path.build() {
                    window.paint_path(path, rgb(0x34485d));
                }
            }
            for destination in destinations.iter() {
                let (x, y) = project(
                    destination.location.longitude,
                    destination.location.latitude,
                );
                let selected = selected == Some(destination.location.key());
                let hovered = hovered == Some(destination.location.key());
                let center = at(x, y);
                let radius = if selected || hovered { 5. } else { 3.5 };
                if selected || hovered {
                    window.paint_quad(
                        fill(
                            Bounds::new(center - point(px(10.), px(10.)), size(px(20.), px(20.))),
                            rgba(0x5ee2b533),
                        )
                        .corner_radii(px(10.)),
                    );
                }
                window.paint_quad(
                    fill(
                        Bounds::new(
                            center - point(px(radius), px(radius)),
                            size(px(radius * 2.), px(radius * 2.)),
                        ),
                        rgb(if selected || hovered {
                            0xffffff
                        } else {
                            0x5ee2b5
                        }),
                    )
                    .corner_radii(px(radius)),
                );
            }
        },
    )
    .w_full()
    .size_full();
    div()
        .id("destination-map")
        .flex_1()
        .min_h_0()
        .w_full()
        .cursor_pointer()
        .child(drawing)
        .on_mouse_down(MouseButton::Left, move |event, window, cx| {
            if let Some(key) = pick(click_bounds.get(), event.position, &click_destinations) {
                on_select(&key, window, cx);
            }
        })
        .on_mouse_move(move |event, window, cx| {
            hover_handler(
                &pick(hit_bounds.get(), event.position, &hover_destinations),
                window,
                cx,
            )
        })
        .on_mouse_exit(move |_, window, cx| exit_handler(&None, window, cx))
}

fn pick(
    bounds: Option<Bounds<Pixels>>,
    cursor: Point<Pixels>,
    destinations: &[Destination],
) -> Option<LocationKey> {
    let bounds = bounds?;
    let fit = MapViewport::fit(f32::from(bounds.size.width), f32::from(bounds.size.height));
    let cursor = cursor - bounds.origin;
    destinations
        .iter()
        .filter_map(|destination| {
            let (x, y) = fit.point(
                destination.location.longitude,
                destination.location.latitude,
            );
            let distance = (f32::from(cursor.x) - x).powi(2) + (f32::from(cursor.y) - y).powi(2);
            (distance <= 12. * 12.).then_some((destination.location.key(), distance))
        })
        .min_by(|a, b| a.1.total_cmp(&b.1))
        .map(|(key, _)| key)
}
pub fn chart(history: Vec<(f64, f64)>) -> impl IntoElement {
    canvas(
        |_, _, _| (),
        move |bounds, _, window, _| {
            let max = history.iter().map(|&(a, b)| a.max(b)).fold(1024., f64::max);
            for (upload, color) in [(false, 0x5ee2b5), (true, 0x79a9ff)] {
                let mut path = PathBuilder::stroke(px(2.));
                for (i, &(download, sent)) in history.iter().enumerate() {
                    let x = i as f32 / 59.;
                    let y = 1. - (if upload { sent } else { download } / max) as f32;
                    let point = point(
                        bounds.origin.x + bounds.size.width * x,
                        bounds.origin.y + bounds.size.height * y,
                    );
                    if i == 0 {
                        path.move_to(point);
                    } else {
                        path.line_to(point);
                    }
                }
                if let Ok(path) = path.build() {
                    window.paint_path(path, rgb(color));
                }
            }
        },
    )
    .w_full()
    .flex_1()
}

#[cfg(test)]
mod tests {
    use super::pick;
    use gpui_kit::{Bounds, point, px, size};
    use rat_core::{Destination, Location};
    #[test]
    fn markers_are_hit_at_their_fitted_positions_after_resize() {
        let destination = Destination {
            location: Location {
                label: "Test".into(),
                city: None,
                country: None,
                latitude: 0.,
                longitude: 90.,
            },
            connections: vec![],
        };
        let bounds = Bounds::new(point(px(50.), px(25.)), size(px(1200.), px(200.)));
        // A 2:1 world is centered at x=400 within this wide viewport.
        // Longitude 90 projects to local x=700, not stretched x=900.
        let key = destination.location.key();
        let destinations = vec![destination];
        assert_eq!(
            pick(Some(bounds), point(px(750.), px(125.)), &destinations),
            Some(key)
        );
        assert_eq!(
            pick(Some(bounds), point(px(950.), px(125.)), &destinations),
            None
        );
        assert_eq!(pick(None, point(px(750.), px(125.)), &destinations), None);
        let resized = Bounds::new(point(px(50.), px(25.)), size(px(400.), px(600.)));
        assert_eq!(
            pick(Some(resized), point(px(350.), px(325.)), &destinations),
            Some(key)
        );
    }
}
