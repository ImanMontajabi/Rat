use gpui_kit::RenderImage;
use rat_core::map::TileKey;
use std::{
    collections::{HashMap, HashSet},
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

struct State {
    revision: u64,
    visible: Vec<TileKey>,
    ready: HashMap<TileKey, (Arc<RenderImage>, Instant)>,
    pending: HashSet<TileKey>,
    failed: HashMap<TileKey, Instant>,
    error: Option<String>,
}
#[derive(Clone)]
pub struct TileStore {
    state: Arc<Mutex<State>>,
}
impl TileStore {
    pub fn new() -> Self {
        let state = Arc::new(Mutex::new(State {
            revision: 0,
            visible: vec![],
            ready: HashMap::new(),
            pending: HashSet::new(),
            failed: HashMap::new(),
            error: None,
        }));
        for _ in 0..2 {
            let weak = Arc::downgrade(&state);
            std::thread::spawn(move || {
                let client = reqwest::blocking::Client::builder()
                    .user_agent("Rat/0.1 (+https://github.com/Phonixoop/Rat)")
                    .timeout(Duration::from_secs(10))
                    .build();
                while let Some(state) = weak.upgrade() {
                    let key = {
                        let mut s = state.lock().unwrap();
                        let key = s.visible.iter().copied().find(|k| {
                            !s.ready.contains_key(k)
                                && !s.pending.contains(k)
                                && s.failed
                                    .get(k)
                                    .is_none_or(|t| t.elapsed() > Duration::from_secs(60))
                        });
                        if let Some(key) = key {
                            s.pending.insert(key);
                        }
                        key
                    };
                    if let Some(key) = key {
                        let result = match &client {
                            Ok(client) => load(client, key),
                            Err(e) => Err(e.to_string()),
                        };
                        let mut s = state.lock().unwrap();
                        s.pending.remove(&key);
                        match result {
                            Ok(image) => {
                                s.revision += 1;
                                s.ready.insert(key, (image, Instant::now()));
                                s.failed.remove(&key);
                                s.error = None;
                            }
                            Err(error) => {
                                s.failed.insert(key, Instant::now());
                                s.error = Some(error);
                            }
                        }
                    } else {
                        drop(state);
                        std::thread::sleep(Duration::from_millis(100));
                    }
                }
            });
        }
        Self { state }
    }
    pub fn frame(
        &self,
        keys: Vec<TileKey>,
    ) -> (HashMap<TileKey, Arc<RenderImage>>, Vec<Arc<RenderImage>>) {
        let mut s = self.state.lock().unwrap();
        s.visible = keys.clone();
        let now = Instant::now();
        let mut ready = HashMap::new();
        for key in keys {
            if let Some((image, time)) = s.ready.get_mut(&key) {
                *time = now;
                ready.insert(key, image.clone());
            }
        }
        let mut dropped = vec![];
        if s.ready.len() > 160 {
            let mut candidates: Vec<_> = s
                .ready
                .iter()
                .filter(|(key, _)| !s.visible.contains(key))
                .map(|(key, (_, time))| (*key, *time))
                .collect();
            candidates.sort_by_key(|(_, time)| *time);
            let count = s.ready.len() - 160;
            for (key, _) in candidates.into_iter().take(count) {
                if let Some((image, _)) = s.ready.remove(&key) {
                    dropped.push(image);
                }
            }
        }
        (ready, dropped)
    }
    pub fn status(&self) -> String {
        let s = self.state.lock().unwrap();
        if let Some(error) = &s.error {
            format!("Map tiles unavailable: {error} · cached tiles remain visible")
        } else if s.visible.iter().any(|k| !s.ready.contains_key(k)) {
            "Loading online map…".into()
        } else {
            "Online map · drag to pan · scroll to zoom".into()
        }
    }
    pub fn peek(&self) -> (u64, HashMap<TileKey, Arc<RenderImage>>) {
        let s = self.state.lock().unwrap();
        (
            s.revision,
            s.ready
                .iter()
                .map(|(key, (image, _))| (*key, image.clone()))
                .collect(),
        )
    }
}
fn cache_root() -> PathBuf {
    std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir)
        .join("RatRust")
        .join("map-tiles")
        .join("openstreetmap")
}
fn load(client: &reqwest::blocking::Client, key: TileKey) -> Result<Arc<RenderImage>, String> {
    let path = cache_root()
        .join(key.z.to_string())
        .join(key.x.to_string())
        .join(format!("{}.png", key.y));
    let metadata = path.with_extension("json");
    let existing = std::fs::read(&path).ok();
    let fresh = std::fs::metadata(&path)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.elapsed().ok())
        .is_some_and(|age| age < Duration::from_secs(7 * 24 * 60 * 60));
    let bytes = if fresh {
        existing.clone().unwrap_or_default()
    } else {
        let info: serde_json::Value = std::fs::read(&metadata)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default();
        let url = format!(
            "https://tile.openstreetmap.org/{}/{}/{}.png",
            key.z, key.x, key.y
        );
        let mut request = client.get(url);
        if existing.is_some() {
            if let Some(etag) = info["etag"].as_str() {
                request = request.header("If-None-Match", etag);
            }
            if let Some(modified) = info["modified"].as_str() {
                request = request.header("If-Modified-Since", modified);
            }
        }
        let response = request.send().map_err(|e| e.to_string())?;
        let bytes = if response.status() == reqwest::StatusCode::NOT_MODIFIED {
            existing.ok_or("Missing cached tile")?
        } else {
            let response = response.error_for_status().map_err(|e| e.to_string())?;
            let headers = response.headers();
            let info = serde_json::json!({"etag":headers.get("etag").and_then(|v|v.to_str().ok()),"modified":headers.get("last-modified").and_then(|v|v.to_str().ok())});
            let bytes = response.bytes().map_err(|e| e.to_string())?.to_vec();
            if let Some(parent) = path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            let _ = std::fs::write(&metadata, info.to_string());
            bytes
        };
        let decoded = image::load_from_memory(&bytes).map_err(|e| e.to_string())?;
        if decoded.width() != 256 || decoded.height() != 256 {
            return Err("Unexpected map tile dimensions".into());
        }
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let _ = std::fs::write(&path, &bytes);
        bytes
    };
    let mut rgba = image::load_from_memory(&bytes)
        .map_err(|e| e.to_string())?
        .to_rgba8();
    for pixel in rgba.pixels_mut() {
        pixel.0.swap(0, 2);
    }
    Ok(Arc::new(RenderImage::new(vec![image::Frame::new(rgba)])))
}
