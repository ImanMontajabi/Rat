#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod glass;
mod layout;
mod motion;
mod origin;
mod tiles;
mod visuals;
use gpui_kit::base::Disableable;
use gpui_kit::component::button::ButtonVariants;
use gpui_kit::{
    component::{
        Theme, ThemeMode,
        button::Button,
        input::{Input, InputEvent, InputState},
    },
    *,
};
use rat_core::{
    BlockRule, Connection, Destination, Direction, LocationKey, Snapshot, destinations,
};
use std::{
    collections::{BTreeSet, VecDeque},
    sync::mpsc,
    time::{Duration, Instant},
};
const BG: u32 = 0x202020;
const PANEL: u32 = 0x292929;
const BORDER: u32 = 0x3b3b3b;
const TEXT: u32 = 0xe5edf7;
const MUTED: u32 = 0xababaf;

enum Command {
    Set(BlockRule, bool),
    Refresh,
}
enum Event {
    Origin(Option<origin::Origin>),
    Sample(Result<Snapshot, String>),
    Rules(Result<Vec<BlockRule>, String>),
    Changed(Result<(), String>),
}
fn worker() -> (mpsc::Sender<Command>, mpsc::Receiver<Event>) {
    let (commands, incoming) = mpsc::channel();
    let (events, outgoing) = mpsc::channel();
    let samples = events.clone();
    std::thread::spawn(move || {
        let _ = samples.send(Event::Origin(origin::locate()));
        let mut monitor = rat_platform::Monitor::default();
        loop {
            if samples
                .send(Event::Sample(monitor.sample().map_err(|e| e.to_string())))
                .is_err()
            {
                break;
            }
            std::thread::sleep(Duration::from_secs(1));
        }
    });
    std::thread::spawn(move || {
        let send_rules = || {
            events.send(Event::Rules(
                rat_platform::read_rules().map_err(|e| e.to_string()),
            ))
        };
        if send_rules().is_err() {
            return;
        }
        loop {
            match incoming.recv_timeout(Duration::from_secs(15)) {
                Ok(Command::Set(rule, block)) => {
                    let _ = events.send(Event::Changed(
                        rat_platform::set_block(&rule, block).map_err(|e| e.to_string()),
                    ));
                    let _ = send_rules();
                }
                Ok(Command::Refresh) => {
                    let _ = send_rules();
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    if send_rules().is_err() {
                        break;
                    }
                }
            }
        }
    });
    (commands, outgoing)
}
#[derive(Clone, Copy, PartialEq)]
enum Page {
    Monitor,
    Rules,
    About,
}
struct Rat {
    page: Page,
    snapshot: Snapshot,
    rules: Vec<BlockRule>,
    selected: Option<Connection>,
    selected_app: Option<String>,
    expanded_apps: BTreeSet<String>,
    app_history: std::collections::BTreeMap<String, VecDeque<f64>>,
    show_chart: bool,
    glass_inspector: bool,
    glass: glass::Glass,
    sort_order: motion::SortOrder,
    animate_rows: bool,
    row_motions: std::collections::BTreeMap<String, motion::RowMotion>,
    recent_connections: std::collections::BTreeMap<String, u64>,
    sample_sequence: u64,
    collapsed_sections: BTreeSet<&'static str>,
    browse_locations: bool,
    settings_tab: usize,
    map_zoom: f32,
    origin: Option<origin::Origin>,
    show_routes: bool,
    map_input: std::rc::Rc<std::cell::RefCell<visuals::MapInput>>,
    map_needs_fit: bool,
    tiles: tiles::TileStore,
    map_pan: (f32, f32),
    selected_destination: Option<LocationKey>,
    hovered_destination: Option<LocationKey>,
    search: Entity<InputState>,
    address: Entity<InputState>,
    rules_search: Entity<InputState>,
    rules_query: String,
    query: String,
    paused: bool,
    blocked_only: bool,
    busy: bool,
    message: String,
    monitor_error: Option<String>,
    rule_error: Option<String>,
    updated: Option<Instant>,
    history: VecDeque<(f64, f64)>,
    commands: mpsc::Sender<Command>,
    events: mpsc::Receiver<Event>,
    _subscriptions: Vec<Subscription>,
    _poll: Task<()>,
}
impl Rat {
    fn new(window: &mut Window, cx: &mut Context<Self>) -> Self {
        let search = cx
            .new(|cx| InputState::new(window, cx).placeholder("Search app, IP, PID or location…"));
        let address = cx.new(|cx| InputState::new(window, cx).placeholder("IPv4 or IPv6 address"));
        let subscription = cx.subscribe_in(&search, window, |this, state, event, _, cx| {
            if matches!(event, InputEvent::Change) {
                this.query = state.read(cx).value().to_string();
                this.map_needs_fit = true;
                cx.notify();
            }
        });
        let rules_search = cx.new(|cx| InputState::new(window, cx).placeholder("Search IP rules…"));
        let rule_subscription =
            cx.subscribe_in(&rules_search, window, |this, state, event, _, cx| {
                if matches!(event, InputEvent::Change) {
                    this.rules_query = state.read(cx).value().to_string();
                    cx.notify();
                }
            });
        let (commands, events) = worker();
        let poll = cx.spawn(async |view, cx| {
            loop {
                cx.background_executor()
                    .timer(Duration::from_millis(250))
                    .await;
                if view
                    .update(cx, |this, cx| {
                        this.poll();
                        cx.notify();
                    })
                    .is_err()
                {
                    break;
                }
            }
        });
        Self {
            page: Page::Monitor,
            snapshot: Snapshot::default(),
            rules: vec![],
            selected: None,
            selected_app: None,
            expanded_apps: BTreeSet::new(),
            app_history: Default::default(),
            show_chart: true,
            glass_inspector: true,
            glass: glass::Glass::new(),
            sort_order: Default::default(),
            animate_rows: true,
            row_motions: Default::default(),
            recent_connections: Default::default(),
            sample_sequence: 0,
            collapsed_sections: Default::default(),
            browse_locations: false,
            settings_tab: 0,
            map_zoom: 1.6,
            origin: None,
            show_routes: true,
            map_input: Default::default(),
            map_needs_fit: true,
            tiles: tiles::TileStore::new(),
            map_pan: (0., 0.),
            selected_destination: None,
            hovered_destination: None,
            search,
            address,
            rules_search,
            rules_query: String::new(),
            query: String::new(),
            paused: false,
            blocked_only: false,
            busy: false,
            message: "Select a connection to inspect its destination.".into(),
            monitor_error: None,
            rule_error: None,
            updated: None,
            history: VecDeque::new(),
            commands,
            events,
            _subscriptions: vec![subscription, rule_subscription],
            _poll: poll,
        }
    }
    fn poll(&mut self) {
        while let Ok(event) = self.events.try_recv() {
            match event {
                Event::Origin(origin) => {
                    self.origin = origin;
                    self.map_needs_fit = true;
                }
                Event::Sample(Ok(snapshot)) if !self.paused => {
                    self.history
                        .push_back((snapshot.received_per_sec, snapshot.sent_per_sec));
                    if self.history.len() > 60 {
                        self.history.pop_front();
                    }
                    if let Some(selected) = &self.selected
                        && let Some(current) = snapshot
                            .connections
                            .iter()
                            .find(|c| c.key() == selected.key())
                    {
                        self.selected = Some(current.clone());
                    }
                    self.sample_sequence += 1;
                    let old_connections = self
                        .snapshot
                        .connections
                        .iter()
                        .map(Connection::key)
                        .collect::<BTreeSet<_>>();
                    for c in &snapshot.connections {
                        if !old_connections.contains(&c.key()) {
                            self.recent_connections
                                .insert(c.process.clone(), self.sample_sequence);
                        }
                    }
                    let mut counts = std::collections::BTreeMap::<String, usize>::new();
                    for c in &snapshot.connections {
                        *counts.entry(c.process.clone()).or_default() += 1;
                    }
                    self.app_history.retain(|name, _| counts.contains_key(name));
                    for (name, count) in counts {
                        let history = self.app_history.entry(name).or_default();
                        history.push_back(count as f64);
                        if history.len() > 60 {
                            history.pop_front();
                        }
                    }
                    self.snapshot = snapshot;
                    self.updated = Some(Instant::now());
                    self.monitor_error = None;
                }
                Event::Sample(Err(e)) => self.monitor_error = Some(e),
                Event::Rules(Ok(rules)) => {
                    self.rules = rules;
                    self.rule_error = None;
                    self.busy = false;
                }
                Event::Rules(Err(e)) => {
                    self.rule_error = Some(e);
                    self.busy = false;
                }
                Event::Changed(result) => {
                    if result.is_err() {
                        self.busy = false;
                    }
                    self.message = match result {
                        Ok(()) => "Windows Firewall accepted the change. Refreshing rules…".into(),
                        Err(e) => e,
                    };
                }
                _ => {}
            }
        }
        if self.map_needs_fit && !self.snapshot.connections.is_empty() {
            self.fit_map_to_destinations();
        }
    }
    fn fit_map_to_destinations(&mut self) {
        let bounds = self.map_input.borrow().bounds;
        if let Some(bounds) = bounds {
            let camera = rat_core::map::Camera {
                width: f32::from(bounds.size.width),
                height: f32::from(bounds.size.height),
                zoom: self.map_zoom,
                pan: self.map_pan,
            };
            let mut points = self
                .visible_destinations()
                .iter()
                .map(|d| (d.location.longitude, d.location.latitude))
                .collect::<Vec<_>>();
            if self.show_routes
                && let Some(origin) = &self.origin
            {
                points.push((origin.longitude, origin.latitude));
            }
            let fitted = camera.fitted(&points);
            self.map_zoom = fitted.zoom;
            self.map_pan = fitted.pan;
            self.map_needs_fit = false;
        }
    }
    fn blocked(&self, connection: &Connection) -> bool {
        self.rules.iter().any(|r| r.ip == connection.remote.ip())
    }
    fn change(&mut self, rule: BlockRule, block: bool) {
        if self.busy {
            return;
        }
        self.busy = true;
        self.message = "Applying Windows Firewall rule…".into();
        if self.commands.send(Command::Set(rule, block)).is_err() {
            self.busy = false;
            self.message = "Firewall worker stopped. Restart Rat.".into();
        }
    }
    fn nav(&self, page: Page, label: &'static str, cx: &Context<Self>) -> impl IntoElement {
        Button::new(label)
            .label(label)
            .toggled(self.page == page)
            .on_click(cx.listener(move |this, _, _, cx| {
                this.page = page;
                cx.notify();
            }))
    }
    fn sidebar(&self, cx: &Context<Self>) -> impl IntoElement {
        div()
            .w(px(250.))
            .h_full()
            .flex_shrink_0()
            .p_4()
            .flex()
            .flex_col()
            .gap_3()
            .bg(rgb(PANEL))
            .border_r_1()
            .border_color(rgb(BORDER))
            .child(
                div()
                    .text_xl()
                    .font_weight(FontWeight::SEMIBOLD)
                    .child("Rules"),
            )
            .child(div().mt_3().text_xs().text_color(rgb(MUTED)).child("RULES"))
            .child(self.nav(Page::Rules, "All IP Rules", cx))
            .child(
                div()
                    .text_xs()
                    .text_color(rgb(MUTED))
                    .child(format!("{} active Windows rules", self.rules.len())),
            )
            .child(div().mt_4().text_xs().text_color(rgb(MUTED)).child("SCOPE"))
            .child(div().child("All applications"))
            .child(
                div()
                    .text_xs()
                    .text_color(rgb(MUTED))
                    .child("Remote IP blocks across all Windows profiles"),
            )
            .child(div().flex_1())
            .child(self.nav(Page::Monitor, "Network Monitor", cx))
            .child(self.nav(Page::About, "Settings", cx))
    }
    fn inspector(&self, cx: &Context<Self>) -> AnyElement {
        let mut pane = div()
            .w(px(310.))
            .flex_shrink_0()
            .h_full()
            .id("inspector-scroll")
            .overflow_y_scroll()
            .p_4()
            .flex()
            .flex_col()
            .gap_3()
            .bg(if self.glass_inspector {
                rgba(0x172132b8)
            } else {
                rgba(0x292929ff)
            })
            .border_l_1()
            .border_color(rgb(BORDER))
            .child(
                div()
                    .font_weight(FontWeight::SEMIBOLD)
                    .child(if self.selected.is_some() {
                        "Connection inspector"
                    } else {
                        "Destination explorer"
                    }),
            );
        if let Some(c) = &self.selected {
            let live = self.snapshot.connections.iter().any(|v| v.key() == c.key());
            pane = pane
                .child(
                    div()
                        .text_lg()
                        .font_weight(FontWeight::SEMIBOLD)
                        .child(c.process.clone()),
                )
                .child(
                    Button::new("inspector-summary")
                        .ghost()
                        .label("Back to summary")
                        .on_click(cx.listener(|this, _, _, cx| {
                            this.selected = None;
                            this.selected_destination = None;
                            this.browse_locations = false;
                            cx.notify();
                        })),
                )
                .child(self.section("connection-process", "Process", cx))
                .children(
                    (!self.collapsed_sections.contains("connection-process")).then(|| {
                        div()
                            .flex()
                            .flex_col()
                            .gap_3()
                            .py_2()
                            .child(detail("APPLICATION", c.process.clone()))
                            .child(detail("PROCESS ID", c.pid.to_string()))
                    }),
                )
                .child(self.section("connection-details", "Connection Details", cx))
                .children(
                    (!self.collapsed_sections.contains("connection-details")).then(|| {
                        div()
                            .flex()
                            .flex_col()
                            .gap_3()
                            .py_2()
                            .child(detail("REMOTE ADDRESS", c.remote.ip().to_string()))
                            .child(detail(
                                "REMOTE PORT / PROTOCOL",
                                format!("{} / TCP", c.remote.port()),
                            ))
                            .child(detail("LOCAL ENDPOINT", c.local.to_string()))
                            .child(detail(
                                "STATE",
                                if live {
                                    c.state.clone()
                                } else {
                                    "No longer in latest sample".into()
                                },
                            ))
                    }),
                )
                .child(self.section("connection-geography", "Geographic Information", cx));
            if !self.collapsed_sections.contains("connection-geography") {
                pane = pane.child(detail(
                    "LOCATION",
                    c.location
                        .as_ref()
                        .map(|l| l.label.clone())
                        .unwrap_or("Unresolved / private address".into()),
                ));
                if let Some(location) = &c.location {
                    let key = location.key();
                    pane = pane.child(
                        Button::new("view-location")
                            .ghost()
                            .label("All apps at this location")
                            .on_click(cx.listener(move |this, _, _, cx| {
                                this.selected = None;
                                this.selected_destination = Some(key);
                                cx.notify();
                            })),
                    );
                }
            }
            pane = pane.child(self.section("connection-firewall", "IP Rules", cx));
            if !self.collapsed_sections.contains("connection-firewall") {
                for direction in [Direction::Outbound, Direction::Inbound] {
                    let rule = BlockRule {
                        ip: c.remote.ip(),
                        direction,
                    };
                    let blocked = self.rules.contains(&rule);
                    pane = pane.child(
                        Button::new(direction.label())
                            .label(format!(
                                "{} {}",
                                if blocked { "Unblock" } else { "Block" },
                                direction.label().to_lowercase()
                            ))
                            .disabled(self.busy || self.rule_error.is_some())
                            .on_click(cx.listener(move |this, _, _, cx| {
                                this.change(rule.clone(), !blocked);
                                cx.notify();
                            })),
                    );
                }
                pane=pane.child(div().text_xs().text_color(rgb(MUTED)).child("IP blocks affect every application using this address. Administrator rights are required."));
            }
        } else {
            let groups = self.visible_destinations();
            if let Some(key) = self.selected_destination {
                pane = pane.child(
                    Button::new("all-locations")
                        .label("All locations")
                        .on_click(cx.listener(|this, _, _, cx| {
                            this.selected_destination = None;
                            cx.notify();
                        })),
                );
                if let Some(destination) = groups.iter().find(|d| d.location.key() == key) {
                    pane = pane
                        .child(
                            div()
                                .text_lg()
                                .font_weight(FontWeight::SEMIBOLD)
                                .child(destination.location.label.clone()),
                        )
                        .child(div().text_xs().text_color(rgb(MUTED)).child(format!(
                            "{} processes · {} server IPs · {} TCP sockets",
                            destination.app_count(),
                            destination.server_count(),
                            destination.connections.len()
                        )))
                        .child(
                            div()
                                .text_xs()
                                .text_color(rgb(MUTED))
                                .child("Select an endpoint to inspect or block its IP."),
                        );
                    let mut apps: std::collections::BTreeMap<(&str, u32), Vec<&Connection>> =
                        std::collections::BTreeMap::new();
                    for c in &destination.connections {
                        apps.entry((&c.process, c.pid)).or_default().push(c);
                    }
                    for (index, ((process, pid), connections)) in apps.into_iter().enumerate() {
                        let mut app = div()
                            .p_3()
                            .rounded_lg()
                            .bg(if self.glass_inspector {
                                rgba(0x17213270)
                            } else {
                                rgba(0x202020ff)
                            })
                            .flex()
                            .flex_col()
                            .gap_2()
                            .child(
                                div()
                                    .font_weight(FontWeight::SEMIBOLD)
                                    .child(process.to_string()),
                            )
                            .child(
                                div()
                                    .text_xs()
                                    .text_color(rgb(MUTED))
                                    .child(format!("PID {pid}")),
                            );
                        let mut endpoints = BTreeSet::new();
                        for (endpoint_index, c) in connections
                            .iter()
                            .filter(|c| endpoints.insert(c.remote))
                            .enumerate()
                        {
                            let c = (*c).clone();
                            app = app.child(
                                Button::new(ElementId::Name(
                                    format!("endpoint-{index}-{endpoint_index}").into(),
                                ))
                                .ghost()
                                .label(c.remote.to_string())
                                .tooltip(format!("Inspect {} → {}", c.process, c.remote))
                                .on_click(cx.listener(
                                    move |this, _, _, cx| {
                                        this.selected = Some(c.clone());
                                        cx.notify();
                                    },
                                )),
                            );
                        }
                        pane = pane.child(app);
                    }
                } else {
                    pane = pane.child(
                        div()
                            .text_color(rgb(MUTED))
                            .child("No matching live connections remain at this location."),
                    );
                }
            } else {
                pane = pane.child(div().text_sm().text_color(rgb(MUTED)).child(
                    "Click a map point or choose a location below to see which apps connect there.",
                ));
                if groups.is_empty() {
                    pane=pane.child(div().text_color(rgb(MUTED)).child("No located destinations match. Unresolved addresses remain in the connection table."));
                }
                for (index, destination) in groups.into_iter().enumerate() {
                    let key = destination.location.key();
                    pane = pane.child(
                        Button::new(("location", index))
                            .ghost()
                            .h_auto()
                            .py_3()
                            .w_full()
                            .accessibility_label(destination.summary())
                            .child(
                                div()
                                    .w_full()
                                    .flex()
                                    .flex_col()
                                    .gap_1()
                                    .child(destination.location.label.clone())
                                    .child(div().text_xs().text_color(rgb(MUTED)).child(format!(
                                        "{} processes · {} servers",
                                        destination.app_count(),
                                        destination.server_count()
                                    ))),
                            )
                            .on_click(cx.listener(move |this, _, _, cx| {
                                this.selected_destination = Some(key);
                                this.selected = None;
                                cx.notify();
                            })),
                    );
                }
            }
        }
        pane.into_any_element()
    }
    fn visible_destinations(&self) -> Vec<Destination> {
        destinations(
            &self
                .snapshot
                .connections
                .iter()
                .filter(|c| {
                    c.matches(&self.query)
                        && self
                            .selected_app
                            .as_ref()
                            .is_none_or(|app| &c.process == app)
                        && (!self.blocked_only || self.blocked(c))
                })
                .cloned()
                .collect::<Vec<_>>(),
        )
    }
    fn rules_page(&self, cx: &Context<Self>) -> AnyElement {
        let mut list = div()
            .id("rules-scroll")
            .overflow_y_scroll()
            .flex_1()
            .flex()
            .flex_col()
            .gap_2();
        list = list.child(
            div()
                .flex()
                .px_3()
                .py_2()
                .gap_4()
                .text_xs()
                .text_color(rgb(MUTED))
                .child(div().w(px(64.)).child("ACTIVE"))
                .child(div().w(px(150.)).child("PROCESS"))
                .child(div().flex_1().child("DESCRIPTION"))
                .child(div().w(px(130.)).child("STATUS")),
        );
        for (index, rule) in self
            .rules
            .iter()
            .filter(|rule| {
                format!("{} {}", rule.ip, rule.direction.label())
                    .to_lowercase()
                    .contains(&self.rules_query.to_lowercase())
            })
            .enumerate()
        {
            let rule = rule.clone();
            list = list.child(
                div()
                    .h(px(64.))
                    .flex_shrink_0()
                    .flex()
                    .items_center()
                    .gap_4()
                    .px_3()
                    .rounded_lg()
                    .bg(rgb(if index % 2 == 0 { 0x2c2c2c } else { BG }))
                    .child(div().w(px(64.)).text_color(rgb(0x73bf8a)).child("Active"))
                    .child(div().w(px(150.)).child("Any Process"))
                    .child(
                        div()
                            .flex_1()
                            .flex()
                            .flex_col()
                            .gap_1()
                            .child(format!(
                                "Block {} to {}",
                                rule.direction.label().to_lowercase(),
                                rule.ip
                            ))
                            .child(
                                div()
                                    .text_xs()
                                    .text_color(rgb(MUTED))
                                    .child("All profiles · All protocols and ports"),
                            ),
                    )
                    .child(
                        Button::new(("remove", index))
                            .ghost()
                            .w(px(130.))
                            .label("Remove rule")
                            .disabled(self.busy)
                            .on_click(cx.listener(move |this, _, _, cx| {
                                this.change(rule.clone(), false);
                                cx.notify();
                            })),
                    ),
            );
        }
        if self.rules.is_empty() {
            list = list.child(div().p_5().text_color(rgb(MUTED)).child(
                "No Rat IP blocks found. Add an address above or select a live connection.",
            ));
        }
        div().p_6().flex_1().min_h_0().flex().flex_col().gap_4()
            .child(div().flex().items_center().gap_4().child(div().flex_1().text_2xl().child(format!("All Rules  ·  {}",self.rules.len()))).child(div().w(px(320.)).child(Input::new(&self.rules_search))))
            .child(div().text_color(rgb(MUTED)).child("Persistent Windows Defender Firewall rules. Each rule covers every app and every port for its IP address."))
            .child(div().flex().gap_3().items_center().child(div().w(px(340.)).child(Input::new(&self.address)))
                .children([Direction::Outbound, Direction::Inbound].map(|direction| {
                    Button::new(direction.label()).label(format!("Block {}", direction.label().to_lowercase())).disabled(self.busy || self.rule_error.is_some())
                        .on_click(cx.listener(move |this, _, _, cx| {
                            match this.address.read(cx).value().trim().parse() {
                                Ok(ip) => {
                                    let rule = BlockRule { ip, direction };
                                    if this.rules.contains(&rule) { this.message = "That IP is already blocked in this direction.".into(); }
                                    else { this.change(rule, true); }
                                }
                                Err(_) => this.message = "Enter one valid IPv4 or IPv6 address (no port or CIDR).".into(),
                            }
                            cx.notify();
                        }))
                }))
                .child(Button::new("refresh").label("Refresh").on_click(cx.listener(|this, _, _, _| { let _ = this.commands.send(Command::Refresh); }))))
            .child(list).into_any_element()
    }
    fn about(&self) -> AnyElement {
        div().flex_1().p_6().flex().flex_col().gap_5()
            .child(div().text_2xl().child("A clear view of your network."))
            .child(detail("MONITORING", "System TCP sockets refresh roughly every second. Includes IPv4 and IPv6. UDP peers and per-process byte rates are not available in this version.".into()))
            .child(detail("FIREWALL", "Launch Rat as administrator to add or remove Windows Defender Firewall blocks. Monitoring works without elevation. Windows owns rule persistence; closing Rat does not remove blocks.".into()))
            .child(detail("OFFLINE LOCATIONS", "Set RAT_GEOIP_DB to the path of a DB-IP or MaxMind City .mmdb database before launch. Rat performs no online geolocation or DNS lookups. Private and unresolved addresses stay in the connection list.".into()))
            .child(detail("GRAPH & RATES", "The activity graph displays interface byte deltas. VPN and virtual adapters may count traffic twice. No per-connection bandwidth or packet contents are inferred.".into()))
            .child(detail("PLATFORM", "Windows-first Rust rewrite · GPUI Kit 0.8.0 · Original macOS Swift app remains in App/ and RatFilter/.".into()))
            .child(detail("CREDITS", "Rat: MIT. GPUI Kit: Apache-2.0. Map geometry: Natural Earth, public domain. GeoIP data is supplied by the user under the provider’s license.".into())).into_any_element()
    }
}
impl Render for Rat {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let content = match self.page {
            Page::Monitor => self.reference_monitor(window, cx),
            Page::Rules => div()
                .flex()
                .flex_1()
                .min_h_0()
                .child(self.sidebar(cx))
                .child(self.rules_page(cx))
                .into_any_element(),
            Page::About => self.settings_view(cx),
        };
        let feedback = self
            .monitor_error
            .as_ref()
            .or(self.rule_error.as_ref())
            .or(self.snapshot.geo_error.as_ref())
            .unwrap_or(&self.message)
            .clone();
        div()
            .size_full()
            .flex()
            .flex_col()
            .bg(rgb(BG))
            .text_color(rgb(TEXT))
            .text_sm()
            .font_family("Segoe UI")
            .child(content)
            .child(
                div()
                    .h(px(28.))
                    .flex_shrink_0()
                    .px_3()
                    .flex()
                    .items_center()
                    .border_t_1()
                    .border_color(rgb(BORDER))
                    .text_xs()
                    .text_color(rgb(MUTED))
                    .child(feedback),
            )
    }
}
fn detail(label: &'static str, value: String) -> impl IntoElement {
    div()
        .flex()
        .flex_col()
        .gap_1()
        .child(div().text_xs().text_color(rgb(MUTED)).child(label))
        .child(value)
}
fn rate(bytes: f64) -> String {
    if bytes >= 1_048_576. {
        format!("{:.1} MB/s", bytes / 1_048_576.)
    } else {
        format!("{:.1} KB/s", bytes / 1024.)
    }
}
fn main() {
    application().with_assets(assets::AllAssets).run(|cx| {
        init(cx);
        Theme::change(ThemeMode::Dark, None, cx);
        cx.on_window_closed(|cx, _| {
            if cx.windows().is_empty() {
                cx.quit();
            }
        })
        .detach();
        let options = WindowOptions {
            window_bounds: Some(WindowBounds::Windowed(Bounds::centered(
                None,
                size(px(1440.), px(920.)),
                cx,
            ))),
            window_min_size: Some(size(px(1180.), px(760.))),
            titlebar: Some(TitlebarOptions {
                title: Some("Rat — Network Observatory".into()),
                ..Default::default()
            }),
            ..Default::default()
        };
        open_window(options, cx, |window, cx| cx.new(|cx| Rat::new(window, cx)))
            .expect("Cannot open Rat window");
        cx.activate(true);
    });
}
