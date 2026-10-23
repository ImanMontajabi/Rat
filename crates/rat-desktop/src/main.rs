#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

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
const BG: u32 = 0x0c111b;
const PANEL: u32 = 0x121a27;
const BORDER: u32 = 0x253247;
const TEXT: u32 = 0xe5edf7;
const MUTED: u32 = 0x9cacc2;
const ACCENT: u32 = 0x5ee2b5;

enum Command {
    Set(BlockRule, bool),
    Refresh,
}
enum Event {
    Sample(Result<Snapshot, String>),
    Rules(Result<Vec<BlockRule>, String>),
    Changed(Result<(), String>),
}
fn worker() -> (mpsc::Sender<Command>, mpsc::Receiver<Event>) {
    let (commands, incoming) = mpsc::channel();
    let (events, outgoing) = mpsc::channel();
    let samples = events.clone();
    std::thread::spawn(move || {
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
    selected_destination: Option<LocationKey>,
    hovered_destination: Option<LocationKey>,
    search: Entity<InputState>,
    address: Entity<InputState>,
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
            selected_destination: None,
            hovered_destination: None,
            search,
            address,
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
            _subscriptions: vec![subscription],
            _poll: poll,
        }
    }
    fn poll(&mut self) {
        while let Ok(event) = self.events.try_recv() {
            match event {
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
            .w(px(192.))
            .h_full()
            .flex()
            .flex_col()
            .flex_shrink_0()
            .p_4()
            .gap_3()
            .bg(rgb(PANEL))
            .border_r_1()
            .border_color(rgb(BORDER))
            .child(div().text_3xl().font_weight(FontWeight::BOLD).child("rat"))
            .child(
                div()
                    .text_xs()
                    .text_color(rgb(MUTED))
                    .child("YOUR NETWORK, REVEALED"),
            )
            .child(div().h(px(24.)))
            .child(self.nav(Page::Monitor, "Network monitor", cx))
            .child(self.nav(Page::Rules, "IP block rules", cx))
            .child(self.nav(Page::About, "Settings & about", cx))
            .child(div().flex_1())
            .child(
                div()
                    .text_sm()
                    .text_color(rgb(ACCENT))
                    .child("Windows Firewall"),
            )
            .child(
                div()
                    .text_xs()
                    .text_color(rgb(MUTED))
                    .child("IP blocks apply to every app. Rules persist after Rat closes."),
            )
            .child(
                div()
                    .text_xs()
                    .mt_3()
                    .text_color(rgb(MUTED))
                    .child("RUST + GPUI KIT  /  0.1"),
            )
    }
    fn metric(label: &'static str, value: String, note: &'static str) -> impl IntoElement {
        div()
            .flex_1()
            .p_4()
            .rounded_lg()
            .bg(rgb(PANEL))
            .border_1()
            .border_color(rgb(BORDER))
            .child(div().text_xs().text_color(rgb(MUTED)).child(label))
            .child(
                div()
                    .text_2xl()
                    .font_weight(FontWeight::SEMIBOLD)
                    .mt_2()
                    .child(value),
            )
            .child(div().text_xs().mt_1().text_color(rgb(MUTED)).child(note))
    }
    fn inspector(&self, cx: &Context<Self>) -> AnyElement {
        let mut pane = div()
            .w(px(270.))
            .flex_shrink_0()
            .h_full()
            .id("inspector-scroll")
            .overflow_y_scroll()
            .p_4()
            .flex()
            .flex_col()
            .gap_3()
            .bg(rgb(PANEL))
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
                .child(div().text_lg().child(c.process.clone()))
                .child(detail("PROCESS ID", c.pid.to_string()))
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
                .child(detail(
                    "LOCATION",
                    c.location
                        .as_ref()
                        .map(|l| l.label.clone())
                        .unwrap_or("Unresolved / private address".into()),
                ))
                .children(c.location.as_ref().map(|location| {
                    let key = location.key();
                    Button::new("view-location")
                        .label("All apps at this location")
                        .on_click(cx.listener(move |this, _, _, cx| {
                            this.selected = None;
                            this.selected_destination = Some(key);
                            cx.notify();
                        }))
                }))
                .child(
                    Button::new("filter-app")
                        .label("Show this app on map")
                        .on_click(cx.listener({
                            let process = c.process.clone();
                            move |this, _, window, cx| {
                                this.search.update(cx, |state, cx| {
                                    state.set_value(process.clone(), window, cx)
                                });
                                this.query = process.clone();
                                cx.notify();
                            }
                        })),
                )
                .child(div().h(px(8.)))
                .child(div().text_sm().child("Control this IP address"));
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
            pane = pane.child(div().text_xs().text_color(rgb(MUTED)).child(
                "Blocking affects all apps using this IP. Administrator rights are required.",
            ));
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
                            .bg(rgb(BG))
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
                .filter(|c| c.matches(&self.query) && (!self.blocked_only || self.blocked(c)))
                .cloned()
                .collect::<Vec<_>>(),
        )
    }
    fn monitor(&self, window: &Window, cx: &Context<Self>) -> AnyElement {
        let groups = self.visible_destinations();
        let selected_location = self
            .selected
            .as_ref()
            .and_then(|c| c.location.as_ref().map(|l| l.key()))
            .or(self.selected_destination);
        let focus = self.hovered_destination.or(selected_location);
        let map_hint = groups
            .iter()
            .find(|d| Some(d.location.key()) == focus)
            .map(Destination::summary)
            .unwrap_or_else(|| {
                "Hover a point for location details · Click to explore connected apps".into()
            });
        let viewport = window.viewport_size();
        let map_width = (f32::from(viewport.width) - 192. - 270. - 40. - 12. - 210.).max(100.);
        let atlas_height = (map_width / 2. + 100.)
            .clamp(250., (f32::from(viewport.height) - 550.).clamp(250., 500.));
        let apps: BTreeSet<_> = self.snapshot.connections.iter().map(|c| c.pid).collect();
        let visible: Vec<_> = self
            .snapshot
            .connections
            .iter()
            .filter(|c| c.matches(&self.query) && (!self.blocked_only || self.blocked(c)))
            .cloned()
            .collect();
        let count = visible.len();
        let row_data = std::rc::Rc::new(visible);
        let selected = self.selected.as_ref().map(Connection::key);
        let rules = self.rules.clone();
        let rows = uniform_list(
            "connections",
            count,
            cx.processor(move |_, range: std::ops::Range<usize>, _, cx| {
                range
                    .map(|index| {
                        let c = row_data[index].clone();
                        let is_selected = selected.as_ref() == Some(&c.key());
                        let blocked = rules.iter().any(|r| r.ip == c.remote.ip());
                        Button::new(("connection", index))
                            .ghost()
                            .accessibility_label(format!(
                                "Inspect {}, PID {}, remote {}",
                                c.process, c.pid, c.remote
                            ))
                            .w_full()
                            .h(px(46.))
                            .px_3()
                            .flex()
                            .items_center()
                            .gap_3()
                            .border_b_1()
                            .border_color(rgb(BORDER))
                            .bg(rgb(if is_selected { 0x21364a } else { PANEL }))
                            .cursor_pointer()
                            .child(div().w(px(150.)).overflow_hidden().child(c.process.clone()))
                            .child(
                                div()
                                    .flex_1()
                                    .overflow_hidden()
                                    .text_color(rgb(MUTED))
                                    .child(c.remote.to_string()),
                            )
                            .child(
                                div().w(px(160.)).text_xs().overflow_hidden().child(
                                    c.location
                                        .as_ref()
                                        .map(|l| l.label.clone())
                                        .unwrap_or("Unresolved / private".into()),
                                ),
                            )
                            .child(
                                div()
                                    .w(px(90.))
                                    .text_xs()
                                    .text_color(rgb(if blocked { 0xff9b9b } else { ACCENT }))
                                    .child(if blocked {
                                        "IP rule set"
                                    } else {
                                        "No IP block"
                                    }),
                            )
                            .on_click(cx.listener(move |this, _, _, cx| {
                                this.selected = Some(c.clone());
                                this.selected_destination = None;
                                cx.notify();
                            }))
                    })
                    .collect::<Vec<_>>()
            }),
        )
        .flex_1()
        .min_h(px(80.));
        let center = div()
            .flex_1()
            .min_w_0()
            .h_full()
            .flex()
            .flex_col()
            .p_5()
            .gap_4()
            .child(
                div()
                    .flex()
                    .gap_3()
                    .child(Self::metric(
                        "TCP CONNECTIONS",
                        self.snapshot.connections.len().to_string(),
                        "Current system snapshot",
                    ))
                    .child(Self::metric(
                        "ACTIVE PROCESSES",
                        apps.len().to_string(),
                        "With remote TCP sockets",
                    ))
                    .child(Self::metric(
                        "DOWNLOAD",
                        rate(self.snapshot.received_per_sec),
                        "All network interfaces",
                    ))
                    .child(Self::metric(
                        "UPLOAD",
                        rate(self.snapshot.sent_per_sec),
                        "All network interfaces",
                    )),
            )
            .child(
                div()
                    .flex()
                    .gap_3()
                    .h(px(atlas_height))
                    .flex_shrink_0()
                    .child(
                        div()
                            .flex_1()
                            .min_w_0()
                            .rounded_lg()
                            .overflow_hidden()
                            .bg(rgb(PANEL))
                            .border_1()
                            .border_color(rgb(BORDER))
                            .flex()
                            .flex_col()
                            .child(
                                div()
                                    .px_4()
                                    .pt_3()
                                    .pb_2()
                                    .flex()
                                    .justify_between()
                                    .child(div().text_sm().child("Destination atlas"))
                                    .child(
                                        Button::new("browse-locations")
                                            .ghost()
                                            .label(format!("{} locations", groups.len()))
                                            .tooltip("Browse locations and connected apps")
                                            .on_click(cx.listener(|this, _, _, cx| {
                                                this.selected = None;
                                                this.selected_destination = None;
                                                cx.notify();
                                            })),
                                    ),
                            )
                            .child(visuals::map(
                                groups,
                                selected_location,
                                self.hovered_destination,
                                cx.listener(|this, key: &LocationKey, _, cx| {
                                    this.selected_destination = Some(*key);
                                    this.selected = None;
                                    cx.notify();
                                }),
                                cx.listener(|this, key: &Option<LocationKey>, _, cx| {
                                    if this.hovered_destination != *key {
                                        this.hovered_destination = *key;
                                        cx.notify();
                                    }
                                }),
                            ))
                            .child(
                                div()
                                    .px_4()
                                    .pt_2()
                                    .min_h(px(34.))
                                    .text_xs()
                                    .text_color(rgb(ACCENT))
                                    .child(map_hint),
                            )
                            .child(div().px_4().pb_3().text_xs().text_color(rgb(MUTED)).child(
                                if self.snapshot.geo_available {
                                    "Offline GeoIP by DB-IP · approximate locations · CC BY 4.0"
                                } else {
                                    "Run scripts/fetch-geoip.ps1 or set RAT_GEOIP_DB, then restart"
                                },
                            )),
                    )
                    .child(
                        div()
                            .w(px(210.))
                            .p_4()
                            .rounded_lg()
                            .bg(rgb(PANEL))
                            .border_1()
                            .border_color(rgb(BORDER))
                            .flex()
                            .flex_col()
                            .gap_3()
                            .child(div().text_sm().child("Network activity"))
                            .child(
                                div()
                                    .text_xs()
                                    .text_color(rgb(MUTED))
                                    .child("Last 60 samples · system-wide"),
                            )
                            .child(visuals::chart(self.history.iter().copied().collect()))
                            .child(div().text_xs().text_color(rgb(ACCENT)).child("Download"))
                            .child(div().text_xs().text_color(rgb(0x79a9ff)).child("Upload")),
                    ),
            )
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap_3()
                    .child(div().flex_1().child(Input::new(&self.search)))
                    .child(
                        Button::new("clear-search")
                            .ghost()
                            .label("Clear search")
                            .disabled(self.query.is_empty())
                            .on_click(cx.listener(|this, _, window, cx| {
                                this.search
                                    .update(cx, |state, cx| state.set_value("", window, cx));
                                this.query.clear();
                                cx.notify();
                            })),
                    )
                    .child(
                        Button::new("filter")
                            .label(if self.blocked_only {
                                "Show all"
                            } else {
                                "IP blocks only"
                            })
                            .on_click(cx.listener(|this, _, _, cx| {
                                this.blocked_only = !this.blocked_only;
                                cx.notify();
                            })),
                    ),
            )
            .child(
                div()
                    .flex()
                    .px_3()
                    .gap_3()
                    .text_xs()
                    .text_color(rgb(MUTED))
                    .child(
                        div()
                            .w(px(150.))
                            .child(format!("PROCESS · {count} sockets")),
                    )
                    .child(div().flex_1().child("REMOTE ENDPOINT"))
                    .child(div().w(px(160.)).child("CITY / COUNTRY"))
                    .child(div().w(px(90.)).child("RAT RULE")),
            )
            .child(if count == 0 {
                div()
                    .flex_1()
                    .p_4()
                    .text_color(rgb(MUTED))
                    .child("No connections match. Waiting for the next sample…")
                    .into_any_element()
            } else {
                rows.into_any_element()
            });
        div()
            .flex()
            .flex_1()
            .min_h_0()
            .child(center)
            .child(self.inspector(cx))
            .into_any_element()
    }
    fn rules_page(&self, cx: &Context<Self>) -> AnyElement {
        let mut list = div()
            .id("rules-scroll")
            .overflow_y_scroll()
            .flex_1()
            .flex()
            .flex_col()
            .gap_2();
        for (index, rule) in self.rules.iter().enumerate() {
            let rule = rule.clone();
            list = list.child(
                div()
                    .flex()
                    .items_center()
                    .gap_4()
                    .p_4()
                    .bg(rgb(PANEL))
                    .rounded_lg()
                    .child(div().flex_1().child(rule.ip.to_string()))
                    .child(div().w(px(120.)).child(rule.direction.label()))
                    .child(div().text_color(rgb(0xff9b9b)).child("Block"))
                    .child(
                        Button::new(("remove", index))
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
            .child(div().text_2xl().child("IP block rules"))
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
        let status = if self.paused {
            "PAUSED"
        } else if self.monitor_error.is_some() {
            "MONITOR ERROR"
        } else if self
            .updated
            .is_some_and(|t| t.elapsed() < Duration::from_secs(5))
        {
            "LIVE"
        } else if self.updated.is_some() {
            "STALE"
        } else {
            "CONNECTING"
        };
        let page = match self.page {
            Page::Monitor => self.monitor(window, cx),
            Page::Rules => self.rules_page(cx),
            Page::About => self.about(),
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
            .bg(rgb(BG))
            .text_color(rgb(TEXT))
            .text_sm()
            .font_family("Segoe UI")
            .child(self.sidebar(cx))
            .child(
                div()
                    .flex_1()
                    .min_w_0()
                    .h_full()
                    .flex()
                    .flex_col()
                    .child(
                        div()
                            .h(px(70.))
                            .flex_shrink_0()
                            .px_5()
                            .border_b_1()
                            .border_color(rgb(BORDER))
                            .flex()
                            .items_center()
                            .gap_4()
                            .child(
                                div()
                                    .flex_1()
                                    .text_xl()
                                    .font_weight(FontWeight::SEMIBOLD)
                                    .child("Network observatory"),
                            )
                            .child(div().text_xs().text_color(rgb(ACCENT)).child(status))
                            .child(
                                Button::new("pause")
                                    .label(if self.paused {
                                        "Resume monitor"
                                    } else {
                                        "Pause monitor"
                                    })
                                    .on_click(cx.listener(|this, _, _, cx| {
                                        this.paused = !this.paused;
                                        cx.notify();
                                    })),
                            ),
                    )
                    .child(page)
                    .child(
                        div()
                            .min_h(px(42.))
                            .flex_shrink_0()
                            .px_5()
                            .py_2()
                            .border_t_1()
                            .border_color(rgb(BORDER))
                            .text_xs()
                            .text_color(rgb(MUTED))
                            .child(feedback),
                    ),
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
    application().with_assets(assets::Assets).run(|cx| {
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
