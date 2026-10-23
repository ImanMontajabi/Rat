use crate::tiles::TileStore;
use gpui_kit::*;
use rat_core::map::{Camera, mercator, tiles_in_region};
use rat_core::{Destination, LocationKey};
use std::{cell::RefCell, rc::Rc, sync::OnceLock};
struct Country {
    rings: Vec<Vec<(f32, f32)>>,
    color: u32,
}
fn land() -> &'static Vec<Country> {
    static LAND: OnceLock<Vec<Country>> = OnceLock::new();
    LAND.get_or_init(|| {
        let json: serde_json::Value =
            serde_json::from_str(include_str!("../countries.geojson")).expect("bundled map");
        let mut countries = vec![];
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
            let mut rings = vec![];
            for polygon in polygons {
                let Some(ring) = polygon[0].as_array() else {
                    continue;
                };
                rings.push(
                    ring.iter()
                        .filter_map(|p| Some(mercator(p[0].as_f64()?, p[1].as_f64()?)))
                        .collect(),
                );
            }
            let properties = &feature["properties"];
            let color = match properties["CONTINENT"].as_str().unwrap_or("") {
                "Africa" => 0x687057,
                "Europe" => 0x3f655b,
                "Asia" => 0x536b60,
                "North America" => 0x48685f,
                "South America" => 0x3e6253,
                "Antarctica" => 0x9aaabb,
                _ => 0x62756a,
            };
            countries.push(Country { rings, color });
        }
        countries
    })
}
#[derive(Default)]
pub struct MapInput {
    pub bounds: Option<Bounds<Pixels>>,
    start: Option<Point<Pixels>>,
    last: Option<Point<Pixels>>,
    moved: bool,
}
pub struct MapOptions {
    pub selected: Option<LocationKey>,
    pub hovered: Option<LocationKey>,
    pub zoom: f32,
    pub pan: (f32, f32),
    pub input: Rc<RefCell<MapInput>>,
    pub tiles: TileStore,
    pub glass: bool,
    pub origin: Option<crate::origin::Origin>,
    pub app_selected: bool,
}
pub enum MapEvent {
    Select(LocationKey),
    Hover(Option<LocationKey>),
    Pan((f32, f32)),
    Zoom {
        factor: f32,
        anchor: (f32, f32),
        viewport: (f32, f32),
    },
}
pub fn map(
    destinations: Vec<Destination>,
    options: MapOptions,
    on_event: impl Fn(&MapEvent, &mut Window, &mut App) + 'static,
) -> impl IntoElement {
    let destinations = Rc::new(destinations);
    let callback = Rc::new(on_event);
    let paint_input = options.input.clone();
    let down_input = options.input.clone();
    let move_input = options.input.clone();
    let up_input = options.input.clone();
    let out_input = options.input.clone();
    let scroll_input = options.input.clone();
    let exit_input = options.input.clone();
    let move_callback = callback.clone();
    let up_callback = callback.clone();
    let exit_callback = callback.clone();
    let up_destinations = destinations.clone();
    let hover_destinations = destinations.clone();
    let MapOptions {
        selected,
        hovered,
        zoom,
        pan,
        tiles,
        glass,
        origin,
        app_selected,
        ..
    } = options;
    let drawing = canvas(
        move |bounds, _, _| {
            paint_input.borrow_mut().bounds = Some(bounds);
        },
        move |bounds, _, window, cx| {
            let camera = Camera {
                width: f32::from(bounds.size.width),
                height: f32::from(bounds.size.height),
                zoom,
                pan,
            };
            let at = |x: f32, y: f32| {
                let (left, top) = camera.origin();
                point(
                    bounds.origin.x + px(left + x * camera.world()),
                    bounds.origin.y + px(top + y * camera.world()),
                )
            };
            // Bundled geometry remains visible while network tiles are unavailable.
            for country in land() {
                for ring in &country.rings {
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
                        window.paint_path(path, rgb(country.color));
                    }
                }
            }
            let tiles_in_view = tiles_in_region(
                camera,
                (
                    0.,
                    if glass { -50. } else { 0. },
                    camera.width + if glass { 310. } else { 0. },
                    camera.height + if glass { 150. } else { 0. },
                ),
            );
            let (ready, dropped) = tiles.frame(tiles_in_view.iter().map(|t| t.key).collect());
            for image in dropped {
                let _ = window.drop_image(image);
            }
            for tile in tiles_in_view {
                if let Some(image) = ready.get(&tile.key) {
                    let rectangle = Bounds::new(
                        bounds.origin + point(px(tile.x), px(tile.y)),
                        size(px(tile.size + 0.5), px(tile.size + 0.5)),
                    );
                    let _ = window.paint_image(
                        bounds,
                        rectangle,
                        Corners::default(),
                        image.clone(),
                        0,
                        false,
                    );
                }
            }
            // Routes use the same camera as tiles, markers and pointer hit tests.
            if let Some(origin) = &origin {
                for destination in destinations.iter() {
                    let (start, control, end) = route(
                        camera,
                        (origin.longitude, origin.latitude),
                        (
                            destination.location.longitude,
                            destination.location.latitude,
                        ),
                    );
                    let active = selected == Some(destination.location.key())
                        || hovered == Some(destination.location.key())
                        || app_selected;
                    let mut path = PathBuilder::stroke(px(if active { 2.5 } else { 1.5 }));
                    path.move_to(bounds.origin + point(px(start.0), px(start.1)));
                    path.curve_to(
                        bounds.origin + point(px(end.0), px(end.1)),
                        bounds.origin + point(px(control.0), px(control.1)),
                    );
                    if let Ok(path) = path.build() {
                        window.paint_path(path, rgba(if active { 0x91d54de0 } else { 0x627fa7a0 }));
                    }
                }
            }
            let mut labels: Vec<Point<Pixels>> = vec![];
            for destination in destinations.iter() {
                let (x, y) = camera.point(
                    destination.location.longitude,
                    destination.location.latitude,
                );
                let center = bounds.origin + point(px(x), px(y));
                if !bounds.contains(&center) {
                    continue;
                }
                let active = selected == Some(destination.location.key())
                    || hovered == Some(destination.location.key());
                let radius = if active { 8. } else { 5.5 };
                window.paint_quad(
                    fill(
                        Bounds::new(
                            center - point(px(radius + 2.), px(radius + 2.)),
                            size(px((radius + 2.) * 2.), px((radius + 2.) * 2.)),
                        ),
                        rgb(if active { 0x3289ec } else { 0x536e8a }),
                    )
                    .corner_radii(px(radius + 2.)),
                );
                window.paint_quad(
                    fill(
                        Bounds::new(
                            center - point(px(radius), px(radius)),
                            size(px(radius * 2.), px(radius * 2.)),
                        ),
                        rgb(0xe5edf7),
                    )
                    .corner_radii(px(radius)),
                );
                if active
                    || labels.iter().all(|p| {
                        f32::from(p.x - center.x).abs() > 110.
                            || f32::from(p.y - center.y).abs() > 30.
                    })
                {
                    let city = destination
                        .location
                        .city
                        .as_deref()
                        .or(destination.location.country.as_deref())
                        .unwrap_or("Unknown");
                    let origin = center + point(px(10.), px(8.));
                    window.paint_quad(
                        fill(
                            Bounds::new(
                                origin - point(px(3.), px(1.)),
                                size(px(city.chars().count() as f32 * 7. + 6.), px(19.)),
                            ),
                            rgba(0x162338e8),
                        )
                        .corner_radii(px(4.)),
                    );
                    label(city, origin, 12., rgb(0xf0f3f7).into(), window, cx);
                    labels.push(center);
                }
            }
            if let Some(origin) = &origin {
                let (x, y) = camera.point(origin.longitude, origin.latitude);
                let center = bounds.origin + point(px(x), px(y));
                if bounds.contains(&center) {
                    window.paint_quad(
                        fill(
                            Bounds::new(center - point(px(18.), px(18.)), size(px(36.), px(36.))),
                            rgba(0x496579ee),
                        )
                        .corner_radii(px(18.)),
                    );
                    // Laptop symbol drawn as vectors so it stays crisp at every DPI.
                    let mut laptop = PathBuilder::stroke(px(1.8));
                    laptop.move_to(center + point(px(-8.), px(5.)));
                    laptop.line_to(center + point(px(-8.), px(-6.)));
                    laptop.line_to(center + point(px(8.), px(-6.)));
                    laptop.line_to(center + point(px(8.), px(5.)));
                    laptop.line_to(center + point(px(-8.), px(5.)));
                    laptop.move_to(center + point(px(-11.), px(7.)));
                    laptop.line_to(center + point(px(11.), px(7.)));
                    if let Ok(path) = laptop.build() {
                        window.paint_path(path, rgb(0xffffff));
                    }
                    let text = format!("This PC · {} (approx.)", origin.city);
                    let text_width = text.chars().count() as f32 * 7. + 6.;
                    let text_origin = bounds.origin
                        + point(
                            px((x + 23.).clamp(6., (camera.width - text_width - 6.).max(6.))),
                            px((y + 24.).clamp(6., (camera.height - 25.).max(6.))),
                        );
                    window.paint_quad(
                        fill(
                            Bounds::new(
                                text_origin - point(px(3.), px(1.)),
                                size(px(text.chars().count() as f32 * 7. + 6.), px(20.)),
                            ),
                            rgba(0x162338eb),
                        )
                        .corner_radii(px(4.)),
                    );
                    label(&text, text_origin, 12., rgb(0xf0f3f7).into(), window, cx);
                }
            }
        },
    )
    .size_full();
    div()
        .id("destination-map")
        .flex_1()
        .min_h_0()
        .w_full()
        .overflow_hidden()
        .cursor(CursorStyle::OpenHand)
        .child(drawing)
        .on_mouse_down(MouseButton::Left, move |event, _, _| {
            let mut input = down_input.borrow_mut();
            input.start = Some(event.position);
            input.last = Some(event.position);
            input.moved = false;
        })
        .on_mouse_move(move |event, window, cx| {
            let mut input = move_input.borrow_mut();
            let Some(bounds) = input.bounds else {
                return;
            };
            if event.dragging()
                && let Some(start) = input.start
            {
                let distance = event.position - start;
                if input.moved || f32::from(distance.x).hypot(f32::from(distance.y)) >= 5. {
                    let last = if input.moved {
                        input.last.unwrap_or(start)
                    } else {
                        start
                    };
                    let delta = event.position - last;
                    input.last = Some(event.position);
                    input.moved = true;
                    let base = f32::from(bounds.size.width)
                        .min(f32::from(bounds.size.height))
                        .max(1.);
                    drop(input);
                    move_callback(
                        &MapEvent::Pan((f32::from(delta.x) / base, f32::from(delta.y) / base)),
                        window,
                        cx,
                    );
                    return;
                }
            } else {
                input.start = None;
                input.last = None;
            }
            drop(input);
            move_callback(
                &MapEvent::Hover(pick_camera(
                    Some(bounds),
                    event.position,
                    &hover_destinations,
                    zoom,
                    pan,
                )),
                window,
                cx,
            );
        })
        .on_mouse_up(MouseButton::Left, move |event, window, cx| {
            let mut input = up_input.borrow_mut();
            let click = input.start.take().is_some() && !input.moved;
            let bounds = input.bounds;
            input.last = None;
            input.moved = false;
            drop(input);
            if click
                && let Some(key) = pick_camera(bounds, event.position, &up_destinations, zoom, pan)
            {
                up_callback(&MapEvent::Select(key), window, cx);
            }
        })
        .on_mouse_up_out(MouseButton::Left, move |_, _, _| {
            let mut input = out_input.borrow_mut();
            input.start = None;
            input.last = None;
            input.moved = false;
        })
        .on_mouse_exit(move |_, window, cx| {
            let mut input = exit_input.borrow_mut();
            input.start = None;
            input.last = None;
            input.moved = false;
            drop(input);
            exit_callback(&MapEvent::Hover(None), window, cx);
        })
        .on_scroll_wheel(move |event, window, cx| {
            if let Some(bounds) = scroll_input.borrow().bounds {
                let delta = match event.delta {
                    ScrollDelta::Lines(p) => p.y * 0.12,
                    ScrollDelta::Pixels(p) => f32::from(p.y) * 0.004,
                };
                let cursor = event.position - bounds.origin;
                callback(
                    &MapEvent::Zoom {
                        factor: delta.clamp(-1., 1.).exp(),
                        anchor: (f32::from(cursor.x), f32::from(cursor.y)),
                        viewport: (f32::from(bounds.size.width), f32::from(bounds.size.height)),
                    },
                    window,
                    cx,
                );
                cx.stop_propagation();
            }
        })
}
type XY = (f32, f32);
fn route(camera: Camera, origin: (f64, f64), destination: (f64, f64)) -> (XY, XY, XY) {
    let mut start = camera.point(origin.0, origin.1);
    let end = camera.point(destination.0, destination.1);
    // Pick the origin's nearest world copy to avoid long arcs across the date line.
    start.0 += ((end.0 - start.0) / camera.world()).round() * camera.world();
    let bend = ((end.0 - start.0).hypot(end.1 - start.1) * 0.22).min(180.);
    let control = ((start.0 + end.0) * 0.5, (start.1 + end.1) * 0.5 - bend);
    (start, control, end)
}
fn pick_camera(
    bounds: Option<Bounds<Pixels>>,
    cursor: Point<Pixels>,
    destinations: &[Destination],
    zoom: f32,
    pan: (f32, f32),
) -> Option<LocationKey> {
    let bounds = bounds?;
    let camera = Camera {
        width: f32::from(bounds.size.width),
        height: f32::from(bounds.size.height),
        zoom,
        pan,
    };
    let cursor = cursor - bounds.origin;
    destinations
        .iter()
        .filter_map(|d| {
            let (x, y) = camera.point(d.location.longitude, d.location.latitude);
            let distance = (f32::from(cursor.x) - x).powi(2) + (f32::from(cursor.y) - y).powi(2);
            (distance <= 144.).then_some((d.location.key(), distance))
        })
        .min_by(|a, b| a.1.total_cmp(&b.1))
        .map(|(key, _)| key)
}

fn label(
    text: &str,
    origin: Point<Pixels>,
    font_size: f32,
    color: Hsla,
    window: &mut Window,
    cx: &mut App,
) {
    let runs = [TextRun {
        len: text.len(),
        font: font("Segoe UI"),
        color,
        ..Default::default()
    }];
    let line = window
        .text_system()
        .shape_line(text.to_string().into(), px(font_size), &runs, None);
    let _ = line.paint(
        origin,
        px(font_size + 4.),
        TextAlign::Left,
        None,
        window,
        cx,
    );
}
pub fn sparkline(history: Vec<f64>) -> impl IntoElement {
    canvas(
        |_, _, _| (),
        move |bounds, _, window, _| {
            let max = history.iter().copied().fold(1., f64::max);
            let width = f32::from(bounds.size.width) / 30.;
            for (i, value) in history.iter().rev().take(30).enumerate() {
                let height = (f32::from(bounds.size.height) * (*value / max) as f32).max(1.);
                let x = bounds.origin.x + bounds.size.width - px((i + 1) as f32 * width);
                window.paint_quad(fill(
                    Bounds::new(
                        point(x, bounds.origin.y + bounds.size.height - px(height)),
                        size(px((width - 1.).max(1.)), px(height)),
                    ),
                    rgb(0x7197d1),
                ));
            }
        },
    )
    .size_full()
}
pub fn chart(history: Vec<(f64, f64)>) -> impl IntoElement {
    canvas(
        |_, _, _| (),
        move |bounds, _, window, _| {
            let max = history.iter().map(|&(a, b)| a.max(b)).fold(1024., f64::max);
            let mid = bounds.origin.y + bounds.size.height / 2.;
            let half = f32::from(bounds.size.height) / 2. - 2.;
            let width = f32::from(bounds.size.width) / 60.;
            let mut baseline = PathBuilder::stroke(px(1.));
            baseline.move_to(point(bounds.origin.x, mid));
            baseline.line_to(point(bounds.origin.x + bounds.size.width, mid));
            if let Ok(path) = baseline.build() {
                window.paint_path(path, rgb(0x56565b));
            }
            for (i, &(download, upload)) in history.iter().rev().take(60).enumerate() {
                let x = bounds.origin.x + bounds.size.width - px((i + 1) as f32 * width);
                for (value, up, color) in [(upload, true, 0xb466dc), (download, false, 0x4898ed)] {
                    let height = (half * (value / max) as f32).max(1.);
                    window.paint_quad(fill(
                        Bounds::new(
                            point(x, if up { mid - px(height) } else { mid }),
                            size(px((width - 1.).max(1.)), px(height)),
                        ),
                        rgb(color),
                    ));
                }
            }
        },
    )
    .size_full()
}

#[cfg(test)]
mod tests {
    use super::{pick_camera, route};
    use gpui_kit::{Bounds, point, px, size};
    use rat_core::{Destination, Location, map::Camera};
    #[test]
    fn routes_follow_camera_and_take_short_path_across_dateline() {
        for camera in [
            Camera {
                width: 800.,
                height: 600.,
                zoom: 1.,
                pan: (0., 0.),
            },
            Camera {
                width: 800.,
                height: 600.,
                zoom: 4.,
                pan: (0.2, -0.1),
            },
        ] {
            let (start, control, end) = route(camera, (179., 30.), (-179., 45.));
            assert_eq!(end, camera.point(-179., 45.));
            assert!((end.0 - start.0).abs() < camera.world() / 50.);
            assert!(control.1 < (start.1 + end.1) / 2.);
            let origin = camera.point(179., 30.);
            assert_eq!(start.1, origin.1);
            let worlds = (start.0 - origin.0) / camera.world();
            assert!((worlds - worlds.round()).abs() < 0.0001);
        }
    }
    #[test]
    fn markers_follow_mercator_camera_after_zoom_and_pan() {
        let d = Destination {
            location: Location {
                label: "Test".into(),
                city: None,
                country: None,
                latitude: 52.,
                longitude: 4.,
            },
            connections: vec![],
        };
        let key = d.location.key();
        let destinations = vec![d];
        for (w, h, z, pan) in [(1200., 200., 2., (0.1, -0.1)), (400., 600., 1., (0., 0.))] {
            let camera = Camera {
                width: w,
                height: h,
                zoom: z,
                pan,
            };
            let (x, y) = camera.point(4., 52.);
            let bounds = Bounds::new(point(px(50.), px(25.)), size(px(w), px(h)));
            assert_eq!(
                pick_camera(
                    Some(bounds),
                    point(px(50. + x), px(25. + y)),
                    &destinations,
                    z,
                    pan
                ),
                Some(key)
            );
            assert_eq!(
                pick_camera(
                    Some(bounds),
                    point(px(75. + x), px(25. + y)),
                    &destinations,
                    z,
                    pan
                ),
                None
            );
        }
    }
}
