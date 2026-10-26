//! In-app material: blur the map's actual tiles behind the inspector on a worker.
use crate::{tiles::TileStore, visuals::MapInput};
use gpui_kit::*;
use rat_core::map::{Camera, TileKey};
use std::{
    cell::RefCell,
    collections::HashMap,
    rc::Rc,
    sync::{Arc, Mutex},
    time::Duration,
};

struct Job {
    camera: Camera,
    crop: (f32, f32, f32, f32),
    tiles: HashMap<TileKey, Arc<RenderImage>>,
}
#[derive(Default)]
struct State {
    signature: Vec<u64>,
    job: Option<Job>,
    image: Option<Arc<RenderImage>>,
    retired: Vec<Arc<RenderImage>>,
}
#[derive(Clone)]
pub struct Glass {
    state: Arc<Mutex<State>>,
}
impl Glass {
    pub fn new() -> Self {
        let state = Arc::new(Mutex::new(State::default()));
        let weak = Arc::downgrade(&state);
        std::thread::spawn(move || {
            while let Some(state) = weak.upgrade() {
                let job = state.lock().unwrap().job.take();
                if let Some(job) = job {
                    let image = render(job);
                    let mut s = state.lock().unwrap();
                    if let Some(old) = s.image.replace(image) {
                        s.retired.push(old);
                    }
                } else {
                    drop(state);
                    std::thread::sleep(Duration::from_millis(20));
                }
            }
        });
        Self { state }
    }
    pub fn element(
        &self,
        input: Rc<RefCell<MapInput>>,
        tiles: TileStore,
        zoom: f32,
        pan: (f32, f32),
    ) -> impl IntoElement {
        let state = self.state.clone();
        canvas(
            |_, _, _| (),
            move |bounds, _, window, _| {
                let Some(map) = input.borrow().bounds else {
                    return;
                };
                let camera = Camera {
                    width: f32::from(map.size.width),
                    height: f32::from(map.size.height),
                    zoom,
                    pan,
                };
                let crop = (
                    camera.width,
                    f32::from(bounds.origin.y - map.origin.y),
                    f32::from(bounds.size.width),
                    f32::from(bounds.size.height),
                );
                let (revision, ready) = tiles.peek();
                let signature = vec![
                    camera.width.to_bits() as u64,
                    camera.height.to_bits() as u64,
                    zoom.to_bits() as u64,
                    pan.0.to_bits() as u64,
                    pan.1.to_bits() as u64,
                    crop.1.to_bits() as u64,
                    crop.2.to_bits() as u64,
                    crop.3.to_bits() as u64,
                    revision,
                ];
                let (image, retired) = {
                    let mut s = state.lock().unwrap();
                    if s.signature != signature {
                        s.signature = signature;
                        s.job = Some(Job {
                            camera,
                            crop,
                            tiles: ready,
                        });
                    }
                    (s.image.clone(), std::mem::take(&mut s.retired))
                };
                for image in retired {
                    let _ = window.drop_image(image);
                }
                if let Some(image) = image {
                    let _ = window.paint_image(bounds, bounds, Corners::default(), image, 0, false);
                }
            },
        )
        .absolute()
        .size_full()
    }
}
fn render(job: Job) -> Arc<RenderImage> {
    let width = (job.crop.2 / 4.).ceil().max(1.) as u32;
    let height = (job.crop.3 / 4.).ceil().max(1.) as u32;
    let z = (job.camera.world() / 256.).log2().round().clamp(0., 18.) as u8;
    let n = 1i32 << z;
    let tile_size = job.camera.world() / n as f32;
    let (left, top) = job.camera.origin();
    let mut buffer = image::RgbaImage::new(width, height);
    for (x, y, pixel) in buffer.enumerate_pixels_mut() {
        let map_x = job.crop.0 + (x as f32 + 0.5) * job.crop.2 / width as f32;
        let map_y = job.crop.1 + (y as f32 + 0.5) * job.crop.3 / height as f32;
        let tx = (map_x - left) / tile_size;
        let ty = (map_y - top) / tile_size;
        let tile_y = ty.floor() as i32;
        let key = TileKey {
            z,
            x: (tx.floor() as i32).rem_euclid(n) as u32,
            y: tile_y.max(0) as u32,
        };
        *pixel = image::Rgba([48, 32, 20, 255]); // BGRA fallback ocean.
        if tile_y >= 0
            && tile_y < n
            && let Some(bytes) = job.tiles.get(&key).and_then(|image| image.as_bytes(0))
        {
            let sx = (tx.rem_euclid(1.) * 256.).floor().clamp(0., 255.) as usize;
            let sy = (ty.rem_euclid(1.) * 256.).floor().clamp(0., 255.) as usize;
            let offset = (sy * 256 + sx) * 4;
            if let Some(source) = bytes.get(offset..offset + 4) {
                pixel.0.copy_from_slice(source);
            }
        }
    }
    let blurred = image::imageops::blur(&buffer, 6.);
    Arc::new(RenderImage::new(vec![image::Frame::new(blurred)]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[::core::prelude::v1::test]
    fn inspector_wraps_map_tiles_and_blurs_edges() {
        let tile = image::RgbaImage::from_fn(256, 256, |x, _| {
            image::Rgba(if x < 128 {
                [0, 0, 0, 255]
            } else {
                [240, 120, 60, 255]
            })
        });
        let result = render(Job {
            camera: Camera {
                width: 256.,
                height: 256.,
                zoom: 1.,
                pan: (0., 0.),
            },
            crop: (256., 0., 256., 256.),
            tiles: HashMap::from([(
                TileKey { z: 0, x: 0, y: 0 },
                Arc::new(RenderImage::new(vec![image::Frame::new(tile)])),
            )]),
        });
        let bytes = result.as_bytes(0).unwrap();
        let pixel = |x: usize| &bytes[(32 * 64 + x) * 4..(32 * 64 + x + 1) * 4];
        assert!(pixel(4)[0] < 5);
        assert!(pixel(31)[0] > 60 && pixel(31)[0] < 180);
        assert!(pixel(59)[0] > 235);
        assert!(bytes.as_chunks::<4>().0.iter().all(|p| p[3] == 255));
    }
}
