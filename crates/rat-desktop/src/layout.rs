use super::*;
use gpui_kit::{assets::IconName, component::checkbox::Checkbox};
use std::collections::BTreeMap;

impl Rat {
    fn clear_selection(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        self.selected_app = None;
        self.map_needs_fit = true;
        self.selected = None;
        self.selected_destination = None;
        self.browse_locations = false;
        self.query.clear();
        self.search
            .update(cx, |state, cx| state.set_value("", window, cx));
        cx.notify();
    }

    pub(super) fn reference_monitor(
        &mut self,
        window: &mut Window,
        cx: &Context<Self>,
    ) -> AnyElement {
        let left_width = (f32::from(window.viewport_size().width) * 0.26).clamp(310., 400.);
        let mut apps: BTreeMap<String, Vec<Connection>> = BTreeMap::new();
        for c in self
            .snapshot
            .connections
            .iter()
            .filter(|c| c.matches(&self.query) && (!self.blocked_only || self.blocked(c)))
        {
            apps.entry(c.process.clone()).or_default().push(c.clone());
        }
        let app_count = apps.len();
        let mut rows = div()
            .id("application-list")
            .flex_1()
            .min_h_0()
            .overflow_y_scroll()
            .flex()
            .flex_col();
        let mut apps: Vec<_> = apps.into_iter().collect();
        apps.sort_by(|(a, ac), (b, bc)| {
            self.sort_order.compare(
                (a, ac.len(), *self.recent_connections.get(a).unwrap_or(&0)),
                (b, bc.len(), *self.recent_connections.get(b).unwrap_or(&0)),
            )
        });
        let names = apps
            .iter()
            .map(|(name, _)| name.clone())
            .collect::<BTreeSet<_>>();
        self.row_motions.retain(|name, _| names.contains(name));
        let now = Instant::now();
        let animate = self.animate_rows && !cx.reduce_motion();
        let mut target_top = 0.;
        for (name, connections) in apps {
            let selected = self.selected_app.as_ref() == Some(&name);
            let expanded = self.expanded_apps.contains(&name);
            let blocked = connections.iter().any(|c| self.blocked(c));
            let servers = connections
                .iter()
                .map(|c| c.remote.ip())
                .collect::<BTreeSet<_>>()
                .len();
            let history = self
                .app_history
                .get(&name)
                .map(|h| h.iter().copied().collect())
                .unwrap_or_default();
            let mut group = div().flex().flex_col().flex_shrink_0().child(div().flex().items_center().h(px(42.)).flex_shrink_0().px_2().gap_1()
                .bg(rgb(if selected {0x294e83} else {PANEL}))
                .child(Button::new(ElementId::Name(format!("expand-{name}").into())).ghost().compact().icon(if expanded {IconName::ChevronDown} else {IconName::ChevronRight})
                    .accessibility_label(format!("{} connections for {name}",if expanded {"Collapse"} else {"Expand"}))
                    .tooltip("Show remote endpoints")
                    .on_click(cx.listener({let name=name.clone(); move |this,_,_,cx| {
                        if !this.expanded_apps.remove(&name) { this.expanded_apps.insert(name.clone()); } cx.notify();
                    }})))
                .child(Button::new(ElementId::Name(format!("select-{name}").into())).ghost().flex_1().min_w_0().h(px(38.))
                    .accessibility_label(format!("{name}, {servers} server IPs, {} TCP sockets",connections.len()))
                    .tooltip(format!("{servers} server IPs · {} TCP sockets. Mini chart: socket count, not bandwidth.",connections.len()))
                    .child(div().flex().items_center().gap_2().w_full()
                        .child(div().size(px(22.)).rounded_md().bg(rgb(0x41434b)).flex().items_center().justify_center().text_xs().font_weight(FontWeight::BOLD).child(name.chars().next().unwrap_or('?').to_uppercase().to_string()))
                        .child(div().flex_1().min_w_0().overflow_hidden().child(name.clone()))
                        .child(div().w(px(52.)).h(px(18.)).child(visuals::sparkline(history)))
                        .child(div().text_xs().text_color(rgb(if blocked {0xff929c} else {MUTED})).child(servers.to_string())))
                    .on_click(cx.listener({let name=name.clone(); move |this,_,_,cx| {
                        this.selected_app=Some(name.clone()); this.map_needs_fit=true; this.selected=None; this.selected_destination=None; this.browse_locations=false; cx.notify();
                    }}))));
            if expanded {
                let mut endpoints = BTreeSet::new();
                for c in connections
                    .iter()
                    .filter(|c| endpoints.insert((c.pid, c.remote)))
                {
                    let c = c.clone();
                    group = group.child(
                        Button::new(ElementId::Name(
                            format!("app-{name}-{}-{}", c.pid, c.remote).into(),
                        ))
                        .ghost()
                        .h(px(48.))
                        .flex_shrink_0()
                        .pl(px(46.))
                        .pr_3()
                        .w_full()
                        .child(
                            div()
                                .flex()
                                .flex_col()
                                .w_full()
                                .gap_1()
                                .child(div().text_xs().child(c.remote.to_string()))
                                .child(
                                    div().text_xs().text_color(rgb(MUTED)).child(
                                        c.location
                                            .as_ref()
                                            .map(|l| l.label.clone())
                                            .unwrap_or("Unresolved / private address".into()),
                                    ),
                                ),
                        )
                        .on_click(cx.listener(move |this, _, _, cx| {
                            this.selected_app = Some(c.process.clone());
                            this.selected = Some(c.clone());
                            this.selected_destination = None;
                            cx.notify();
                        })),
                    );
                }
            }
            let endpoint_count = connections
                .iter()
                .map(|c| (c.pid, c.remote))
                .collect::<BTreeSet<_>>()
                .len();
            let (offset, active) = self
                .row_motions
                .entry(name.clone())
                .or_insert_with(|| motion::RowMotion::new(target_top, now))
                .offset(target_top, now, animate);
            if active {
                window.request_animation_frame();
            }
            rows = rows.child(group.relative().top(px(offset)));
            target_top += 42.
                + if expanded {
                    endpoint_count as f32 * 48.
                } else {
                    0.
                };
        }
        if app_count == 0 {
            rows = rows.child(
                div()
                    .p_4()
                    .text_color(rgb(MUTED))
                    .child("No applications match this search."),
            );
        }
        let mut left = div()
            .w(px(left_width))
            .flex_shrink_0()
            .h_full()
            .flex()
            .flex_col()
            .bg(rgb(PANEL))
            .border_r_1()
            .border_color(rgb(BORDER))
            .child(
                div()
                    .h(px(50.))
                    .px_3()
                    .flex_shrink_0()
                    .flex()
                    .items_center()
                    .gap_1()
                    .child(
                        div()
                            .flex_1()
                            .font_weight(FontWeight::SEMIBOLD)
                            .child("Network Monitor"),
                    )
                    .child(
                        Button::new("open-rules")
                            .ghost()
                            .compact()
                            .icon(IconName::SlidersHorizontal)
                            .tooltip("IP rules")
                            .accessibility_label("Open IP rules")
                            .on_click(cx.listener(|this, _, _, cx| {
                                this.page = Page::Rules;
                                cx.notify();
                            })),
                    )
                    .child(
                        Button::new("toggle-chart")
                            .ghost()
                            .compact()
                            .icon(IconName::ChartNoAxesColumn)
                            .tooltip("Show / hide traffic chart")
                            .accessibility_label("Toggle traffic chart")
                            .toggled(self.show_chart)
                            .on_click(cx.listener(|this, _, _, cx| {
                                this.show_chart = !this.show_chart;
                                cx.notify();
                            })),
                    )
                    .child(
                        Button::new("open-settings")
                            .ghost()
                            .compact()
                            .icon(IconName::Settings)
                            .tooltip("Settings")
                            .accessibility_label("Open settings")
                            .on_click(cx.listener(|this, _, _, cx| {
                                this.page = Page::About;
                                cx.notify();
                            })),
                    ),
            )
            .child(div().px_3().pb_3().child(Input::new(&self.search)))
            .child(
                div()
                    .px_3()
                    .pb_2()
                    .flex()
                    .gap_2()
                    .child(
                        Button::new("all-apps")
                            .ghost()
                            .compact()
                            .label("All apps")
                            .toggled(self.selected_app.is_none())
                            .on_click(
                                cx.listener(|this, _, window, cx| this.clear_selection(window, cx)),
                            ),
                    )
                    .child(
                        Button::new("blocked-apps")
                            .ghost()
                            .compact()
                            .label("IP blocks")
                            .toggled(self.blocked_only)
                            .on_click(cx.listener(|this, _, _, cx| {
                                this.blocked_only = !this.blocked_only;
                                cx.notify();
                            })),
                    )
                    .child(div().flex_1())
                    .child(
                        Button::new("pause-monitor")
                            .ghost()
                            .compact()
                            .icon(if self.paused {
                                IconName::Play
                            } else {
                                IconName::Pause
                            })
                            .accessibility_label("Pause or resume monitoring")
                            .tooltip(if self.paused {
                                "Resume monitoring"
                            } else {
                                "Pause monitoring"
                            })
                            .on_click(cx.listener(|this, _, _, cx| {
                                this.paused = !this.paused;
                                cx.notify();
                            })),
                    ),
            )
            .child(
                div()
                    .px_3()
                    .pb_2()
                    .flex()
                    .items_center()
                    .gap_1()
                    .child(div().text_xs().text_color(rgb(MUTED)).child("Sort"))
                    .children(
                        [
                            motion::SortOrder::Name,
                            motion::SortOrder::Recent,
                            motion::SortOrder::Count,
                        ]
                        .into_iter()
                        .map(|order| {
                            Button::new(order.label())
                                .ghost()
                                .compact()
                                .label(order.label())
                                .toggled(self.sort_order == order)
                                .tooltip(match order {
                                    motion::SortOrder::Name => "Stable alphabetical order",
                                    motion::SortOrder::Recent => {
                                        "Most recently observed new TCP connection"
                                    }
                                    motion::SortOrder::Count => {
                                        "Most current TCP sockets (not bandwidth)"
                                    }
                                })
                                .on_click(cx.listener(move |this, _, _, cx| {
                                    this.sort_order = order;
                                    cx.notify();
                                }))
                        }),
                    ),
            )
            .child(rows);
        if self.show_chart {
            left = left.child(
                div()
                    .p_3()
                    .border_t_1()
                    .border_color(rgb(BORDER))
                    .flex_shrink_0()
                    .flex()
                    .flex_col()
                    .gap_2()
                    .child(self.traffic_badges())
                    .child(
                        div()
                            .h(px(130.))
                            .rounded_lg()
                            .bg(rgb(0x1c1c1e))
                            .p_2()
                            .child(visuals::chart(self.history.iter().copied().collect())),
                    )
                    .child(
                        div()
                            .flex()
                            .justify_between()
                            .text_xs()
                            .text_color(rgb(MUTED))
                            .child("System-wide traffic")
                            .child("Last 60 samples"),
                    ),
            );
        }
        left = left.child(
            div()
                .h(px(28.))
                .px_3()
                .flex_shrink_0()
                .flex()
                .items_center()
                .justify_between()
                .text_xs()
                .text_color(rgb(MUTED))
                .child(format!("{app_count} apps"))
                .child(if self.paused {
                    "Paused"
                } else if self.monitor_error.is_some() {
                    "Monitor error"
                } else if self
                    .updated
                    .is_some_and(|t| t.elapsed() < Duration::from_secs(5))
                {
                    "Live · TCP"
                } else {
                    "Connecting…"
                }),
        );

        let groups = self.visible_destinations();
        let selected_location = self
            .selected
            .as_ref()
            .and_then(|c| c.location.as_ref().map(|l| l.key()))
            .or(self.selected_destination);
        let focus = self.hovered_destination.or(selected_location);
        let hint = groups
            .iter()
            .find(|d| Some(d.location.key()) == focus)
            .map(Destination::summary)
            .unwrap_or_else(|| "Select an app or a destination to inspect its connections".into());
        let center = div()
            .flex_1()
            .min_w_0()
            .h_full()
            .flex()
            .flex_col()
            .overflow_hidden()
            .bg(rgb(0x101d36))
            .child(
                div()
                    .h(px(50.))
                    .px_4()
                    .flex_shrink_0()
                    .flex()
                    .items_center()
                    .justify_between()
                    .border_b_1()
                    .border_color(rgba(0xffffff18))
                    .child(
                        div().font_weight(FontWeight::SEMIBOLD).child(
                            self.selected_app
                                .clone()
                                .unwrap_or("All Applications".into()),
                        ),
                    )
                    .child(
                        Button::new("map-locations")
                            .ghost()
                            .compact()
                            .label(format!("{} locations", groups.len()))
                            .on_click(cx.listener(|this, _, _, cx| {
                                this.browse_locations = true;
                                this.selected = None;
                                this.selected_destination = None;
                                cx.notify();
                            })),
                    ),
            )
            .child(visuals::map(
                groups,
                visuals::MapOptions {
                    selected: selected_location,
                    hovered: self.hovered_destination,
                    zoom: self.map_zoom,
                    pan: self.map_pan,
                    input: self.map_input.clone(),
                    tiles: self.tiles.clone(),
                    glass: self.glass_inspector,
                    origin: self.origin.clone().filter(|_| self.show_routes),
                    app_selected: self.selected_app.is_some(),
                },
                cx.listener(|this, event: &visuals::MapEvent, _, cx| {
                    match event {
                        visuals::MapEvent::Select(key) => {
                            this.selected_destination = Some(*key);
                            this.selected = None;
                        }
                        visuals::MapEvent::Hover(key) => {
                            if this.hovered_destination == *key {
                                return;
                            }
                            this.hovered_destination = *key;
                        }
                        visuals::MapEvent::Pan(delta) => {
                            this.map_pan.0 += delta.0;
                            this.map_pan.1 += delta.1;
                            this.map_needs_fit = false;
                            this.hovered_destination = None;
                        }
                        visuals::MapEvent::Zoom {
                            factor,
                            anchor,
                            viewport,
                        } => {
                            let camera = rat_core::map::Camera {
                                width: viewport.0,
                                height: viewport.1,
                                zoom: this.map_zoom,
                                pan: this.map_pan,
                            }
                            .zoom_at(*factor, *anchor);
                            this.map_zoom = camera.zoom;
                            this.map_pan = camera.pan;
                            this.map_needs_fit = false;
                        }
                    }
                    cx.notify();
                }),
            ))
            .child(
                div()
                    .px_3()
                    .py_2()
                    .flex_shrink_0()
                    .flex()
                    .items_center()
                    .gap_2()
                    .bg(rgba(0x121b2ae0))
                    .child(
                        div()
                            .flex_1()
                            .min_w_0()
                            .text_xs()
                            .text_color(rgb(0xc2ccd9))
                            .child(hint),
                    )
                    .child(
                        Button::new("map-west")
                            .ghost()
                            .compact()
                            .icon(IconName::ChevronLeft)
                            .tooltip("Pan west")
                            .accessibility_label("Pan west")
                            .on_click(cx.listener(|this, _, _, cx| {
                                this.map_pan.0 += 0.12;
                                cx.notify();
                            })),
                    )
                    .child(
                        Button::new("map-east")
                            .ghost()
                            .compact()
                            .icon(IconName::ChevronRight)
                            .tooltip("Pan east")
                            .accessibility_label("Pan east")
                            .on_click(cx.listener(|this, _, _, cx| {
                                this.map_pan.0 -= 0.12;
                                cx.notify();
                            })),
                    )
                    .child(
                        Button::new("map-north")
                            .ghost()
                            .compact()
                            .icon(IconName::ChevronUp)
                            .tooltip("Pan north")
                            .accessibility_label("Pan north")
                            .on_click(cx.listener(|this, _, _, cx| {
                                this.map_pan.1 += 0.12;
                                cx.notify();
                            })),
                    )
                    .child(
                        Button::new("map-south")
                            .ghost()
                            .compact()
                            .icon(IconName::ChevronDown)
                            .tooltip("Pan south")
                            .accessibility_label("Pan south")
                            .on_click(cx.listener(|this, _, _, cx| {
                                this.map_pan.1 -= 0.12;
                                cx.notify();
                            })),
                    )
                    .child(
                        Button::new("zoom-out")
                            .ghost()
                            .compact()
                            .icon(IconName::Minus)
                            .tooltip("Zoom out")
                            .accessibility_label("Zoom out")
                            .on_click(cx.listener(|this, _, _, cx| {
                                this.map_zoom = (this.map_zoom / 1.25).max(0.75);
                                cx.notify();
                            })),
                    )
                    .child(
                        Button::new("zoom-in")
                            .ghost()
                            .compact()
                            .icon(IconName::Plus)
                            .tooltip("Zoom in")
                            .accessibility_label("Zoom in")
                            .on_click(cx.listener(|this, _, _, cx| {
                                this.map_zoom = (this.map_zoom * 1.25).min(4096.);
                                cx.notify();
                            })),
                    )
                    .child(
                        Button::new("map-fit")
                            .ghost()
                            .compact()
                            .label("Fit")
                            .tooltip("Fit visible destinations")
                            .on_click(cx.listener(|this, _, _, cx| {
                                this.fit_map_to_destinations();
                                cx.notify();
                            })),
                    ),
            )
            .child(
                div()
                    .px_3()
                    .py_1()
                    .flex_shrink_0()
                    .text_xs()
                    .text_color(rgb(MUTED))
                    .child(self.tiles.status())
                    .child(
                        Button::new("map-attribution")
                            .ghost()
                            .compact()
                            .label("© OpenStreetMap contributors · GeoIP: DB-IP (CC BY 4.0)")
                            .on_click(|_, _, cx| {
                                cx.open_url("https://www.openstreetmap.org/copyright")
                            }),
                    ),
            );
        let right = if self.selected.is_some()
            || self.selected_destination.is_some()
            || self.browse_locations
        {
            self.inspector(cx)
        } else {
            self.monitor_summary(cx)
        };
        div()
            .size_full()
            .flex()
            .min_h_0()
            .child(left)
            .child(center)
            .child(
                div()
                    .relative()
                    .w(px(310.))
                    .h_full()
                    .flex_shrink_0()
                    .overflow_hidden()
                    .children(self.glass_inspector.then(|| {
                        self.glass.element(
                            self.map_input.clone(),
                            self.tiles.clone(),
                            self.map_zoom,
                            self.map_pan,
                        )
                    }))
                    .child(right),
            )
            .into_any_element()
    }

    fn traffic_badges(&self) -> impl IntoElement {
        div()
            .flex()
            .gap_2()
            .child(
                div()
                    .flex_1()
                    .rounded_lg()
                    .px_3()
                    .py_2()
                    .bg(rgb(0x69418f))
                    .flex()
                    .flex_col()
                    .gap_1()
                    .child(div().text_xs().child("↑ sent"))
                    .child(
                        div()
                            .font_weight(FontWeight::SEMIBOLD)
                            .child(rate(self.snapshot.sent_per_sec)),
                    ),
            )
            .child(
                div()
                    .flex_1()
                    .rounded_lg()
                    .px_3()
                    .py_2()
                    .bg(rgb(0x315b9d))
                    .flex()
                    .flex_col()
                    .gap_1()
                    .child(div().text_xs().child("↓ received"))
                    .child(
                        div()
                            .font_weight(FontWeight::SEMIBOLD)
                            .child(rate(self.snapshot.received_per_sec)),
                    ),
            )
    }

    pub(super) fn section(
        &self,
        id: &'static str,
        label: &'static str,
        cx: &Context<Self>,
    ) -> impl IntoElement {
        let closed = self.collapsed_sections.contains(id);
        Button::new(id)
            .ghost()
            .w_full()
            .mt_3()
            .icon(if closed {
                IconName::ChevronRight
            } else {
                IconName::ChevronDown
            })
            .label(label)
            .accessibility_label(format!(
                "{} {label}",
                if closed { "Expand" } else { "Collapse" }
            ))
            .bg(rgba(0xffffff14))
            .on_click(cx.listener(move |this, _, _, cx| {
                if !this.collapsed_sections.remove(id) {
                    this.collapsed_sections.insert(id);
                }
                cx.notify();
            }))
    }
    fn monitor_summary(&self, cx: &Context<Self>) -> AnyElement {
        let connections: Vec<_> = self
            .snapshot
            .connections
            .iter()
            .filter(|c| {
                self.selected_app
                    .as_ref()
                    .is_none_or(|app| &c.process == app)
                    && c.matches(&self.query)
            })
            .collect();
        let processes = connections
            .iter()
            .map(|c| c.pid)
            .collect::<BTreeSet<_>>()
            .len();
        let servers = connections
            .iter()
            .map(|c| c.remote.ip())
            .collect::<BTreeSet<_>>()
            .len();
        let mut pane = div()
            .id("summary-scroll")
            .w(px(310.))
            .h_full()
            .flex_shrink_0()
            .overflow_y_scroll()
            .bg(if self.glass_inspector {
                rgba(0x172132b8)
            } else {
                rgba(0x292929ff)
            })
            .border_l_1()
            .border_color(rgb(BORDER))
            .p_4()
            .flex()
            .flex_col()
            .gap_2()
            .child(
                div()
                    .text_xl()
                    .font_weight(FontWeight::SEMIBOLD)
                    .child(self.selected_app.clone().unwrap_or("Summary".into())),
            )
            .child(
                div()
                    .text_xs()
                    .text_color(rgb(MUTED))
                    .child(format!("{processes} processes · {servers} server IPs")),
            )
            .child(self.traffic_badges())
            .child(
                div()
                    .text_xs()
                    .text_color(rgb(MUTED))
                    .child("Current system-wide rates"),
            )
            .child(self.section("summary-connections", "Connections", cx))
            .children(
                (!self.collapsed_sections.contains("summary-connections")).then(|| {
                    div()
                        .flex()
                        .flex_col()
                        .gap_3()
                        .py_2()
                        .child(detail("TCP SOCKETS", connections.len().to_string()))
                        .child(detail("RAT IP BLOCKS", self.rules.len().to_string()))
                        .child(detail(
                            "UNRESOLVED LOCATIONS",
                            connections
                                .iter()
                                .filter(|c| c.location.is_none())
                                .count()
                                .to_string(),
                        ))
                }),
            )
            .child(self.section("summary-statistics", "Statistics", cx));
        let mut statistics = div().flex().flex_col().gap_2();
        let mut apps = BTreeMap::<String, usize>::new();
        let mut countries = BTreeMap::<String, usize>::new();
        for c in &connections {
            *apps.entry(c.process.clone()).or_default() += 1;
            if let Some(country) = c.location.as_ref().and_then(|l| l.country.as_ref()) {
                *countries.entry(country.clone()).or_default() += 1;
            }
        }
        let mut apps: Vec<_> = apps.into_iter().collect();
        apps.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        statistics = statistics.child(
            div()
                .mt_2()
                .text_xs()
                .text_color(rgb(MUTED))
                .child("Top Processes"),
        );
        for (index, (name, count)) in apps.into_iter().take(5).enumerate() {
            statistics = statistics.child(
                Button::new(("top-process", index))
                    .ghost()
                    .accessibility_label(format!("Show {name} on map, {count} TCP sockets"))
                    .h_auto()
                    .py_2()
                    .w_full()
                    .child(
                        div()
                            .flex()
                            .flex_col()
                            .w_full()
                            .gap_1()
                            .child(name.clone())
                            .child(
                                div()
                                    .text_xs()
                                    .text_color(rgb(MUTED))
                                    .child(format!("{count} TCP sockets")),
                            ),
                    )
                    .on_click(cx.listener(move |this, _, _, cx| {
                        this.selected_app = Some(name.clone());
                        this.map_needs_fit = true;
                        this.selected = None;
                        this.selected_destination = None;
                        cx.notify();
                    })),
            );
        }
        let mut countries: Vec<_> = countries.into_iter().collect();
        countries.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        statistics = statistics.child(
            div()
                .mt_3()
                .text_xs()
                .text_color(rgb(MUTED))
                .child("Top Countries"),
        );
        for (country, count) in countries.into_iter().take(5) {
            statistics = statistics.child(
                div().py_1().child(country).child(
                    div()
                        .text_xs()
                        .text_color(rgb(MUTED))
                        .child(format!("{count} TCP sockets")),
                ),
            );
        }
        if !self.collapsed_sections.contains("summary-statistics") {
            pane = pane.child(statistics);
        }
        pane.child(
            Button::new("summary-locations")
                .label("Explore locations")
                .on_click(cx.listener(|this, _, _, cx| {
                    this.browse_locations = true;
                    cx.notify();
                })),
        )
        .into_any_element()
    }

    pub(super) fn settings_view(&self, cx: &Context<Self>) -> AnyElement {
        let tabs = [
            ("General", IconName::Settings),
            ("Monitor", IconName::Activity),
            ("Security", IconName::Shield),
            ("About", IconName::Info),
        ];
        let header = div()
            .h(px(108.))
            .flex_shrink_0()
            .bg(rgb(PANEL))
            .border_b_1()
            .border_color(rgb(BORDER))
            .flex()
            .items_center()
            .justify_center()
            .gap_4()
            .child(
                Button::new("settings-back")
                    .ghost()
                    .icon(IconName::ArrowLeft)
                    .label("Monitor")
                    .on_click(cx.listener(|this, _, _, cx| {
                        this.page = Page::Monitor;
                        cx.notify();
                    })),
            )
            .children(tabs.into_iter().enumerate().map(|(index, (label, icon))| {
                Button::new(("settings-tab", index))
                    .ghost()
                    .accessibility_label(label)
                    .h(px(68.))
                    .w(px(112.))
                    .toggled(self.settings_tab == index)
                    .child(
                        div()
                            .flex()
                            .flex_col()
                            .items_center()
                            .gap_2()
                            .child(icon)
                            .child(label),
                    )
                    .on_click(cx.listener(move |this, _, _, cx| {
                        this.settings_tab = index;
                        cx.notify();
                    }))
            }));
        let content=match self.settings_tab {
            0=>div().flex().flex_col().gap_6()
                .child(detail("NETWORK MONITOR",if self.paused {"Paused"} else {"Running · system TCP snapshots"}.into()))
                .child(detail("FIREWALL", "IP rules are enforced by Windows Defender Firewall. Run Rat as administrator to change them.".into()))
                .child(detail("OPERATION", "Observe live connections and create inbound or outbound blocks for individual IP addresses.".into()))
                .child(Button::new("settings-rules").label("Edit IP rules…").on_click(cx.listener(|this,_,_,cx|{this.page=Page::Rules;cx.notify();}))).into_any_element(),
            1=>div().flex().flex_col().gap_6()
                .child(Checkbox::new("settings-routes").label("Show curved connection routes").checked(self.show_routes).on_change(cx.listener(|this,value:&bool,_,cx|{this.show_routes = *value;this.map_needs_fit=true;cx.notify();})))
                .child(detail("THIS PC LOCATION", self.origin.as_ref().map(|o|format!("Approximate: {} · based on Windows time zone, not GPS. Curves illustrate connections, not packet routes.",o.city)).unwrap_or("No representative location for this Windows time zone; routes are hidden.".into())))
                .child(Checkbox::new("settings-glass").label("Translucent map inspector").checked(self.glass_inspector).on_change(cx.listener(|this,value:&bool,_,cx|{this.glass_inspector = *value;cx.notify();})))
                .child(Checkbox::new("settings-animation").label("Animate application reordering").checked(self.animate_rows).on_change(cx.listener(|this,value:&bool,_,cx|{this.animate_rows = *value;cx.notify();})))
                .child(Checkbox::new("settings-chart").label("Show traffic chart").checked(self.show_chart).on_change(cx.listener(|this,value:&bool,_,cx|{this.show_chart = *value;cx.notify();})))
                .child(detail("TRAFFIC DISPLAY", "Purple bars show uploaded bytes/s; blue bars show downloaded bytes/s. These are system-wide interface rates.".into()))
                .child(detail("APPLICATION MINI CHARTS", "Per-app charts show the number of TCP sockets over the last 30 samples. They do not represent per-app bandwidth.".into()))
                .child(detail("MAP", "Online OpenStreetMap tiles with locally resolved city markers. Drag to pan, scroll to zoom at the mouse pointer, or use Fit to frame destinations.".into()))
                .child(Button::new("reset-map-settings").label("Reset map view").on_click(cx.listener(|this,_,_,cx|{this.map_zoom=1.;this.map_pan=(0.,0.);cx.notify();}))).into_any_element(),
            2=>div().flex().flex_col().gap_6()
                .child(detail("ENFORCEMENT", "Windows Defender Firewall · Persistent IP rules across all profiles.".into()))
                .child(detail("SCOPE", "A block applies to every application using its remote IP. Closing Rat does not remove the rule.".into()))
                .child(detail("PRIVACY", "GeoIP lookups run locally. OpenStreetMap receives requests for visible map tiles; destination IPs and packet contents are not sent to the tile provider.".into()))
                .child(Button::new("settings-refresh").label("Refresh firewall rules").on_click(cx.listener(|this,_,_,_|{let _=this.commands.send(Command::Refresh);}))).into_any_element(),
            _=>self.about(),
        };
        div()
            .flex_1()
            .min_h_0()
            .flex()
            .flex_col()
            .child(header)
            .child(
                div()
                    .id("settings-content")
                    .flex_1()
                    .overflow_y_scroll()
                    .p_8()
                    .flex()
                    .justify_center()
                    .child(div().w(px(720.)).max_w_full().py_4().child(content)),
            )
            .into_any_element()
    }
}
