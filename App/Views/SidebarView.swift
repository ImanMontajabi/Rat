import SwiftUI
import Charts
import AppKit
import RatFilterCore

/// The Network Monitor's left pane. Layout follows Little Snitch's: a row of three icon buttons (filter menu,
/// traffic chart, inspector), a search field with chips and a time-range menu, the process list, and at the
/// bottom the sent / received pills over the traffic chart.
struct SidebarView: View {
    @EnvironmentObject var ledger: Ledger
    @Environment(\.openWindow) private var openWindow
    @ObservedObject private var settings = AppSettings.shared
    @Binding var selection: MonitorSelection?
    @Binding var showChart: Bool
    @Binding var showInspector: Bool
    /// The search field, its chips and the time range; the map shows what they leave.
    @Binding var filter: MonitorFilter

    @State private var expandedGroups = Set<String>()

    // MARK: data

    private var query: (text: String, route: RouteFilter) { filter.query }
    private var range: TimeRange { filter.range }
    private var filtered: [AppEntry] { filter.apps(ledger, settings: settings) }

    private var rows: [AppEntry] {
        let list = filtered
        switch settings.sortKey {
        case .name: return list.sorted { $0.identity.name.localizedCaseInsensitiveCompare($1.identity.name) == .orderedAscending }
        case .traffic: return list.sorted { $0.totalIn + $0.totalOut > $1.totalIn + $1.totalOut }
        case .recent: return list.sorted { ($0.lastActive, $1.identity.name) > ($1.lastActive, $0.identity.name) }
        }
    }

    /// `country` is the ISO code of a country group, for its rule button.
    private struct Group: Identifiable { let id: String; let title: String; let apps: [AppEntry]; var country: String? = nil }

    private var groups: [Group] {
        var d: [String: [AppEntry]] = [:]
        var codes: [String: String] = [:]
        for a in filtered {
            let keys: Set<String>
            switch settings.groupBy {
            case .domain: keys = Set(a.remotes.filter { !isLocalAddress($0.address) }.map { registrableDomain($0.host) })
            case .country:
                var k = Set<String>()
                for r in a.remotes {
                    guard let g = r.geo else { continue }
                    let title = [g.flag, g.country].filter { !$0.isEmpty }.joined(separator: " ")
                    k.insert(title)
                    if let cc = r.country ?? Rule.countryCode(g.countryCode) { codes[title] = cc }
                }
                keys = k
            case .process: keys = []
            }
            for k in keys { d[k, default: []].append(a) }
        }
        return d.map { Group(id: $0.key, title: $0.key, apps: $0.value, country: codes[$0.key]) }.sorted { $0.apps.count > $1.apps.count }
    }

    // MARK: body

    var body: some View {
        VStack(spacing: 0) {
            toolbar
            HStack(spacing: 10) {
                searchField
                localSwitch
            }
            .padding(.horizontal, 14).padding(.bottom, 10)
            ScrollView {
                LazyVStack(spacing: 0) {
                    if settings.groupBy == .process {
                        ForEach(rows) { app in ProcessRow(app: app, selection: $selection, filter: query.route, hideLocal: filter.hideLocal) }
                    } else {
                        ForEach(groups) { g in groupRow(g) }
                    }
                }
                .padding(.horizontal, 8)
            }
            footer
        }
        .background(.ultraThinMaterial)
    }

    private func groupRow(_ g: Group) -> some View {
        VStack(spacing: 0) {
            HStack(spacing: 8) {
                Image(systemName: "chevron.right").font(.caption2).rotationEffect(.degrees(expandedGroups.contains(g.id) ? 90 : 0)).foregroundStyle(.secondary).frame(width: 14)
                Image(systemName: settings.groupBy == .domain ? "globe" : "flag").frame(width: 24)
                Text(g.title).lineLimit(1).font(.system(size: 14, weight: .medium))
                Spacer()
                if let cc = g.country {
                    // A rule for every server in the country, for any process: the editor opens on it.
                    Button {
                        ledger.rules.draft = ledger.rules.newCountryRule(cc, app: nil)
                        openWindow(id: "rules")
                    } label: { Image(systemName: "hand.raised") }
                    .buttonStyle(.borderless).help("New rule for servers in \(Countries.label(cc))…")
                    .accessibilityLabel("New rule for servers in \(Countries.name(cc))")
                    .accessibilityIdentifier("country-rule-\(cc)")
                }
                Text("\(g.apps.count)").font(.caption).foregroundStyle(.secondary)
            }
            .padding(.vertical, 8).padding(.horizontal, 6).contentShape(Rectangle())
            .onTapGesture { if !expandedGroups.insert(g.id).inserted { expandedGroups.remove(g.id) } }
            if expandedGroups.contains(g.id) {
                ForEach(g.apps) { app in ProcessRow(app: app, selection: $selection, filter: query.route, hideLocal: filter.hideLocal).padding(.leading, 18) }
            }
        }
    }

    /// Three icon buttons, in the reference order: filter menu, traffic chart, inspector.
    private var toolbar: some View {
        HStack(spacing: 16) {
            Spacer()
            // AppKit's menu: this pane redraws on every pass, and a SwiftUI menu was rebuilt under an open submenu.
            ViewOptionsMenu().fixedSize()
            Button { showChart.toggle() } label: { Image(systemName: "chart.bar") }
                .help(showChart ? "Hide Traffic Chart" : "Show Traffic Chart")
            Button { showInspector.toggle() } label: { Image(systemName: "info.circle") }
                .help(showInspector ? "Hide Inspector" : "Show Inspector")
        }
        .buttonStyle(.plain).font(.system(size: 16))
        // The window's traffic-light buttons sit above this row.
        .padding(.top, 34).padding(.horizontal, 18).padding(.bottom, 8)
    }

    private var searchField: some View {
        HStack(spacing: 8) {
            Image(systemName: "magnifyingglass").foregroundStyle(.secondary)
            TextField("Search", text: $filter.search).textFieldStyle(.plain).accessibilityIdentifier("search-field")
            chip("arrow.down.left.circle", on: $filter.onlyIncoming, help: "Only apps accepting incoming connections").accessibilityIdentifier("only-incoming")
            chip("xmark.rectangle", on: $filter.onlyDenied, help: "Only denied apps").accessibilityIdentifier("only-denied")
            Menu {
                Picker("Route", selection: $filter.route) { ForEach(RouteFilter.allCases) { Label($0.title, systemImage: $0.symbol).tag($0) } }.pickerStyle(.inline)
            } label: {
                Image(systemName: filter.route.symbol).foregroundStyle(filter.route == .all ? Color.secondary : .accentColor)
            }
            .menuStyle(.borderlessButton).menuIndicator(.hidden).fixedSize()
            .help("Only connections through a VPN or a proxy (or type vpn / proxy in the search field)")
            .accessibilityIdentifier("route-filter")
            Menu {
                ForEach(TimeRange.allCases) { r in Button(r.title) { filter.range = r } }
            } label: { Label(range.rawValue, systemImage: "clock").font(.callout) }
            .menuStyle(.borderlessButton).fixedSize()
            .accessibilityIdentifier("time-range")
        }
        .padding(.horizontal, 12).padding(.vertical, 8)
        .background(.white.opacity(0.08), in: Capsule())
    }

    /// Local connections on or off (`MonitorFilter.hideLocal`, remembered as `AppSettings.hideLocal`): a labeled
    /// switch beside the search field, on while they are shown.
    private var localSwitch: some View {
        Toggle(isOn: Binding(get: { !filter.hideLocal }, set: { filter.hideLocal = !$0 })) {
            Text("Local").font(.callout).foregroundStyle(.secondary)
        }
        .toggleStyle(.switch).controlSize(.mini).fixedSize()
        .help("Local connections: this Mac (loopback), the local network (LAN, link-local) and Bonjour (mDNS, multicast). Turn off to hide them in the list, the map and the Summary.")
        .accessibilityLabel("Local connections").accessibilityIdentifier("show-local")
    }

    private func chip(_ symbol: String, on: Binding<Bool>, help: String) -> some View {
        Button { on.wrappedValue.toggle() } label: {
            Image(systemName: symbol).foregroundStyle(on.wrappedValue ? Color.accentColor : .secondary)
        }.buttonStyle(.plain).help(help)
    }

    private var footer: some View {
        VStack(spacing: 8) {
            HStack(spacing: 8) {
                Pill(kind: .up, text: formatBytes(ledger.sessionOut), label: "sent")
                Pill(kind: .down, text: formatBytes(ledger.sessionIn), label: "received")
            }
            if showChart { TrafficChart(range: range) }
            if ledger.enforcer.helperInstalled && ledger.enforcer.helperOutdated {
                Label("The firewall helper needs an update (Settings > Security)", systemImage: "exclamationmark.shield")
                    .font(.caption).foregroundStyle(.orange)
            } else if !ledger.deniedAppPaths.isEmpty {
                if !ledger.enforcer.helperInstalled {
                    Label("Deny is not enforced: install the firewall helper (Settings > Security)", systemImage: "exclamationmark.shield")
                        .font(.caption).foregroundStyle(.orange)
                } else if ledger.enforcer.status == nil {
                    Label("Deny is not enforced: the firewall helper is not running", systemImage: "exclamationmark.shield")
                        .font(.caption).foregroundStyle(.orange)
                } else if let st = ledger.enforcer.status, st.blockedPorts > 0 {
                    Label("Blocking \(st.blockedPorts) connections of denied apps", systemImage: "shield.checkered")
                        .font(.caption).foregroundStyle(.secondary)
                }
            }
            HStack {
                Text(settings.groupBy == .process ? "\(rows.count) app\(rows.count == 1 ? "" : "s")" : "\(groups.count) group\(groups.count == 1 ? "" : "s")").font(.caption).foregroundStyle(.secondary)
                Spacer()
                Text("Last \(range.title)").font(.caption).foregroundStyle(.secondary)
            }
            // How many passes the window has seen, for the UI tests (a menu must stay open across them).
            Text("Passes").font(.system(size: 1)).foregroundStyle(.clear).allowsHitTesting(false).frame(height: 1)
                .accessibilityValue("\(ledger.passes)").accessibilityIdentifier("monitor-passes")
        }
        .padding(10)
    }
}

/// What the Network Monitor shows: the search, the chips next to it and the time range. The list and the map
/// apply the same filter, so the map draws only the listed apps' matching connections.
struct MonitorFilter: Equatable {
    var search = ""
    var onlyIncoming = false
    var onlyDenied = false
    /// Leave out connections that stay near this Mac, and apps and processes that have only those (`AppSettings.hideLocal`).
    var hideLocal = false
    /// The route chip; "vpn" or "proxy" in the search overrides it.
    var route: RouteFilter = .all
    var range: TimeRange = .fiveMinutes

    /// A search or a chip narrows what is shown (the time range alone does not: it is the chart's window).
    var isActive: Bool { !search.trimmingCharacters(in: .whitespaces).isEmpty || onlyIncoming || onlyDenied || route != .all }

    /// The search text without its filter words, and the route filter in effect.
    var query: (text: String, route: RouteFilter) { RouteFilter.parse(search, chip: route) }

    /// The apps the list shows.
    @MainActor func apps(_ ledger: Ledger, settings: AppSettings, now: Date = Date()) -> [AppEntry] {
        let (text, route) = query
        let cutoff = now.addingTimeInterval(-range.seconds)
        var list = ledger.apps.filter { $0.lastActive >= cutoff && ($0.totalIn + $0.totalOut > 0 || !$0.remotes.isEmpty || $0.listening > 0) }
        if !settings.includeLocalNetwork {
            list = list.filter { $0.remotes.isEmpty || $0.remotes.contains { !isLocalAddress($0.address) } || $0.totalIn + $0.totalOut > 0 }
        }
        if !settings.includeNetworkExtensions { list = list.filter { !$0.identity.isExtension } }
        if !settings.includeOtherUsers { list = list.filter { !$0.otherUsers } }
        if onlyIncoming { list = list.filter { $0.listening > 0 || $0.remotes.contains(where: \.incoming) } }
        if onlyDenied { list = list.filter { ledger.rules.policy(for: $0.identity.ruleKey) == .deny } }
        if hideLocal { list = list.filter { !$0.onlyLocal } }
        let shown = { (r: RemoteHost) in !(hideLocal && r.isLocal) }
        if route != .all { list = list.filter { $0.remotes.contains { shown($0) && route.matches($0) } } }
        if !text.isEmpty {
            list = list.filter { a in
                a.identity.name.localizedCaseInsensitiveContains(text) ||
                a.processes.keys.contains { $0.localizedCaseInsensitiveContains(text) } ||
                a.remotes.contains { shown($0) && Self.remote($0, contains: text) }
            }
        }
        return list
    }

    /// Whether the map draws one of a listed app's connections: it is on the route asked for and, when the
    /// search names neither the app nor the connection's process, the search finds the connection itself
    /// ("Paris" draws only the lines to Paris).
    func matches(_ r: RemoteHost, of app: AppEntry) -> Bool {
        let (text, route) = query
        guard route.matches(r), !(hideLocal && r.isLocal) else { return false }
        guard !text.isEmpty, !app.identity.name.localizedCaseInsensitiveContains(text) else { return true }
        return (r.process?.localizedCaseInsensitiveContains(text) ?? false) || Self.remote(r, contains: text)
    }

    private static func remote(_ r: RemoteHost, contains text: String) -> Bool {
        r.host.localizedCaseInsensitiveContains(text) || r.address.localizedCaseInsensitiveContains(text) ||
            (r.geo?.country.localizedCaseInsensitiveContains(text) ?? false) || (r.geo?.city.localizedCaseInsensitiveContains(text) ?? false) ||
            (r.via?.serverGeo?.city.localizedCaseInsensitiveContains(text) ?? false)
    }
}

/// Which connections the list shows: all, or only those through a VPN or a proxy.
enum RouteFilter: String, CaseIterable, Identifiable {
    case all, vpn, proxy, either
    var id: String { rawValue }
    var title: String { ["all": "All Connections", "vpn": "Through a VPN", "proxy": "Through a Proxy", "either": "Through a VPN or Proxy"][rawValue]! }
    var symbol: String { ["all": "point.3.connected.trianglepath.dotted", "vpn": "lock.shield", "proxy": "arrow.triangle.branch", "either": "shield.lefthalf.filled"][rawValue]! }
    /// Splits the filter words off a search ("vpn", "proxy", or "is:vpn", "is:proxy"); both words mean either.
    /// Without one, the chip's choice applies.
    static func parse(_ search: String, chip: RouteFilter) -> (text: String, route: RouteFilter) {
        var vpn = false, proxy = false, words: [Substring] = []
        for w in search.split(separator: " ") {
            switch w.lowercased() {
            case "vpn", "is:vpn": vpn = true
            case "proxy", "is:proxy": proxy = true
            default: words.append(w)
            }
        }
        let route: RouteFilter = vpn && proxy ? .either : vpn ? .vpn : proxy ? .proxy : chip
        return (words.joined(separator: " "), route)
    }

    func matches(_ r: RemoteHost) -> Bool {
        switch self {
        case .all: return true
        case .vpn: return r.isVPN
        case .proxy: return r.isProxied
        case .either: return r.isVPN || r.isProxied
        }
    }
}

/// An app and, expanded, its tree: the main process's connections, then each other process (helpers, XPC
/// services; for the macOS row, every service) with its own connections. Each level can be selected, which scopes
/// the map and the inspector.
struct ProcessRow: View {
    @EnvironmentObject var ledger: Ledger
    let app: AppEntry
    @Binding var selection: MonitorSelection?
    /// Shows only the connections through a VPN or a proxy.
    var filter: RouteFilter = .all
    /// Leaves out connections that stay near this Mac, and processes that have only those.
    var hideLocal = false
    @State private var open = false
    @State private var openProcesses = Set<String>()

    init(app: AppEntry, selection: Binding<MonitorSelection?>, filter: RouteFilter = .all, hideLocal: Bool = false, open: Bool = false, openProcesses: Set<String> = []) {
        self.app = app; _selection = selection; self.filter = filter; self.hideLocal = hideLocal
        // Snapshot tests start a row open.
        _open = State(initialValue: open); _openProcesses = State(initialValue: openProcesses)
    }

    private var selectedHere: Bool { selection?.appID == app.id }

    var body: some View {
        let tree: (direct: [RemoteHost], processes: [ProcessNode]) = open ? filtered(app.tree) : ([], [])
        VStack(spacing: 0) {
            HStack(spacing: 8) {
                Disclosure(open: open, label: app.identity.name) { withAnimation(.easeInOut(duration: 0.15)) { open.toggle() } }
                Image(nsImage: app.identity.icon).resizable().frame(width: 24, height: 24)
                Text(app.identity.name).lineLimit(1).font(.system(size: 14, weight: .medium)).layoutPriority(1)
                RouteSummaryBadges(remotes: app.remotes).layoutPriority(0.5) // after the name, before the spacer
                if app.identity.isExtension {
                    Text("EXT").font(.system(size: 9, weight: .semibold)).padding(.horizontal, 4).padding(.vertical, 1)
                        .overlay(RoundedRectangle(cornerRadius: 3).stroke(.secondary)).foregroundStyle(.secondary)
                }
                Spacer(minLength: 4)
                Sparkline(rates: app.rates)
                if app.identity.isSystem && ledger.rules.policy(for: app.identity.ruleKey) == nil {
                    // Denying every system service at once would cut DNS, updates and push for every app.
                    Image(systemName: "lock.fill").font(.system(size: 11)).foregroundStyle(.secondary).frame(width: 46)
                        .help("System services are not allowed or denied as a whole: denying them would break DNS for every app. Use a rule for one service in the Rules window.")
                } else {
                    PolicyToggle(policy: ledger.rules.policy(for: app.identity.ruleKey)) { ledger.setPolicy($0, for: app.id) }
                }
            }
            .padding(.vertical, 7).padding(.horizontal, 6)
            .background(selectedHere && selection?.process == nil && selection?.remote == nil ? Color.accentColor : .clear, in: RoundedRectangle(cornerRadius: 8))
            .contentShape(Rectangle())
            .onTapGesture { select(MonitorSelection(appID: app.id)) }
            .accessibilityElement(children: .contain)
            .accessibilityAddTraits(.isButton)
            .accessibilityAction { select(MonitorSelection(appID: app.id)) }
            .accessibilityIdentifier("app-row-\(app.identity.name)")
            if open {
                VStack(alignment: .leading, spacing: 1) {
                    if tree.direct.isEmpty && tree.processes.isEmpty { Text("No connections").foregroundStyle(.secondary).padding(.leading, 44) }
                    ForEach(tree.direct.prefix(30)) { r in remoteRow(r, indent: 44, process: app.mainProcess) }
                    ForEach(tree.processes) { node in processRow(node) }
                }
                .font(.caption).padding(.trailing, 8).padding(.vertical, 4)
            }
        }
    }

    private func select(_ s: MonitorSelection) { selection = selection == s ? nil : s }

    private func filtered(_ t: (direct: [RemoteHost], processes: [ProcessNode])) -> (direct: [RemoteHost], processes: [ProcessNode]) {
        guard filter != .all || hideLocal else { return t }
        let keep = { (r: RemoteHost) in filter.matches(r) && !(hideLocal && r.isLocal) }
        // The route filter shows only processes with such connections; Hide Local hides those that had only local
        // ones (a process with traffic and no connection listed stays).
        let nodes = t.processes.compactMap { n -> ProcessNode? in
            var m = n; m.remotes = n.remotes.filter(keep)
            return m.remotes.isEmpty && (filter != .all || !n.remotes.isEmpty) ? nil : m
        }
        return (t.direct.filter(keep), nodes)
    }

    @ViewBuilder private func processRow(_ node: ProcessNode) -> some View {
        let isOpen = openProcesses.contains(node.name)
        let s = MonitorSelection(appID: app.id, process: node.name)
        HStack(spacing: 6) {
            Disclosure(open: isOpen, label: node.name) { if !openProcesses.insert(node.name).inserted { openProcesses.remove(node.name) } }
            Image(systemName: app.identity.isSystem ? "gearshape.2" : "gearshape").foregroundStyle(.secondary)
            // The fullest form that fits: tags spelled out, then as symbols, then without the pid; only then is a long
            // name ("Google Chrome Helper (Aperitif)") cut in the middle. The count and size are never cut or wrapped.
            ViewThatFits(in: .horizontal) {
                processLabel(node, pids: true, tags: true)
                processLabel(node, pids: true, tags: false)
                processLabel(node, pids: false, tags: false)
            }
            rowPolicy(app.ruleTarget(process: node.name), service: node.name, subject: "this process")
        }
        .padding(.vertical, 3).padding(.leading, 30).padding(.trailing, 4)
        .background(selection == s ? Color.accentColor.opacity(0.85) : .clear, in: RoundedRectangle(cornerRadius: 6))
        .contentShape(Rectangle())
        .onTapGesture { select(s) }
        .accessibilityElement(children: .contain)
        .accessibilityAddTraits(.isButton)
        .accessibilityAction { select(s) }
        .accessibilityIdentifier("process-row-\(node.name)")
        if isOpen {
            if node.remotes.isEmpty { Text("No connections").foregroundStyle(.secondary).padding(.leading, 70) }
            ForEach(node.remotes.prefix(30)) { r in remoteRow(r, indent: 70, process: node.name) }
        }
    }

    private func remoteRow(_ r: RemoteHost, indent: CGFloat, process: String?) -> some View {
        let s = MonitorSelection(appID: app.id, process: process, remote: r.id)
        return HStack(spacing: 6) {
            // The fullest form that fits: tags spelled out, then the port without its service name, then the tags as
            // symbols. Only when even that is too wide is the host cut, in the middle; the port and size never are.
            ViewThatFits(in: .horizontal) {
                connectionLabel(r, tags: true, service: true)
                connectionLabel(r, tags: true, service: false)
                connectionLabel(r, tags: false, service: true)
                connectionLabel(r, tags: false, service: false)
            }
            .help(r.geo.map { "\($0.place)\(r.incoming ? "" : " · \(r.host)")" } ?? r.host)
            // The row reads as one element (its label carries the tags); its ✗/✓ stay buttons of their own.
            .accessibilityElement(children: .combine)
            .accessibilityAddTraits(.isButton)
            .accessibilityAction { select(s) }
            .accessibilityIdentifier("remote-row-\(r.host)")
            HStack(spacing: 0) { rowPolicy(app.ruleTarget(process: process, remote: r), service: r.process ?? process, subject: "this connection") }
                .accessibilityElement(children: .contain)
                .accessibilityIdentifier("remote-policy-\(r.host)")
        }
        .padding(.vertical, 2).padding(.leading, indent).padding(.trailing, 4)
        .background(selection == s ? Color.accentColor.opacity(0.7) : .clear, in: RoundedRectangle(cornerRadius: 5))
        .contentShape(Rectangle())
        .onTapGesture { select(s) }
    }

    private func processLabel(_ node: ProcessNode, pids: Bool, tags: Bool) -> some View {
        HStack(spacing: 6) {
            Text(node.name).lineLimit(1).truncationMode(.middle).font(.caption.weight(.medium)).layoutPriority(1)
            RouteSummaryBadges(remotes: node.remotes, symbolsOnly: !tags)
            if pids, !node.pids.isEmpty {
                Text(verbatim: node.pids.count == 1 ? "pid \(node.pids[0])" : "\(node.pids.count) processes").foregroundStyle(.secondary).lineLimit(1).fixedSize()
            }
            Spacer(minLength: 4)
            Text(verbatim: "\(node.remotes.count)").foregroundStyle(.secondary).monospacedDigit().fixedSize().help("Connections")
            if node.totalIn + node.totalOut > 0 { Text(formatBytes(node.totalIn + node.totalOut)).foregroundStyle(.secondary).monospacedDigit().lineLimit(1).fixedSize() }
        }
    }

    private func connectionLabel(_ r: RemoteHost, tags: Bool, service: Bool) -> some View {
        HStack(spacing: 6) {
            if let flag = r.geo?.flag, !flag.isEmpty { Text(flag).accessibilityHidden(true) }
            Text(r.host).lineLimit(1).truncationMode(.middle)
            HStack(spacing: tags ? 4 : 3) {
                ForEach(RouteBadges.items(r, compact: true), id: \.self) { RouteBadge(item: $0, symbolOnly: !tags) }
            }
            Spacer(minLength: 4)
            Text(verbatim: "\(r.proto) \(r.port)" + (service ? serviceSuffix(proto: r.proto, port: r.port) : ""))
                .foregroundStyle(.secondary).monospacedDigit().lineLimit(1).fixedSize()
            if r.bytesIn + r.bytesOut > 0 {
                Text(formatBytes(r.bytesIn + r.bytesOut)).foregroundStyle(.secondary).monospacedDigit().lineLimit(1).fixedSize()
                    .help("\(formatBytes(r.bytesIn)) received, \(formatBytes(r.bytesOut)) sent on the open connections")
            }
        }
    }

    /// The ✗/✓ of a process or connection row: its own choice, or the one it follows from its process or app shown
    /// muted. None for a row no rule can name (a local connection), and a lock for services that work for every app.
    @ViewBuilder private func rowPolicy(_ target: RulesModel.Target?, service: String?, subject: String) -> some View {
        if let target {
            let p = ledger.rules.rowPolicy(target)
            if p.own == nil, app.identity.isSystem, let service, SharedServices.note(for: service) != nil {
                Image(systemName: "lock.fill").font(.system(size: 9)).foregroundStyle(.secondary).frame(width: 44)
                    .help("\(service) works for every app: denying it would cut them all. Use a rule for one service in the Rules window.")
                    .accessibilityIdentifier("policy-locked")
            } else {
                PolicyToggle(policy: p.own, inherited: p.inherited, compact: true, subject: subject) { ledger.setPolicy($0, for: target) }
            }
        } else {
            Color.clear.frame(width: 44, height: 1)
        }
    }
}

/// The View Options button and its menu (group, sort, the three Show options, Float on Top), in AppKit. A SwiftUI
/// `Menu` here is rebuilt by every pass that redraws the sidebar (every 1.5 s), even as a view of its own: an open
/// Group By or Sort By submenu then lost the item under the pointer, and a click on it did nothing. This `NSMenu` is
/// built once and owned by AppKit while it is open; its checkmarks are read from `AppSettings` when it opens.
struct ViewOptionsMenu: NSViewRepresentable {
    func makeCoordinator() -> ViewOptionsMenuController { ViewOptionsMenuController() }

    func makeNSView(context: Context) -> NSButton {
        let b = NSButton(image: NSImage(systemSymbolName: "slider.horizontal.3", accessibilityDescription: "View Options") ?? NSImage(),
                         target: context.coordinator, action: #selector(ViewOptionsMenuController.show(_:)))
        b.isBordered = false
        b.symbolConfiguration = NSImage.SymbolConfiguration(pointSize: 16, weight: .regular)
        b.contentTintColor = .labelColor
        b.toolTip = "View options"
        b.setAccessibilityLabel("View Options")
        b.setAccessibilityIdentifier("view-options")
        b.setContentHuggingPriority(.required, for: .horizontal)
        return b
    }

    func updateNSView(_ view: NSButton, context: Context) {}
}

@MainActor
final class ViewOptionsMenuController: NSObject, NSMenuDelegate {
    private var settings: AppSettings { .shared }
    private(set) lazy var menu: NSMenu = build()

    @objc func show(_ sender: NSButton) {
        menu.popUp(positioning: nil, at: NSPoint(x: 0, y: sender.bounds.maxY + 4), in: sender)
    }

    private func build() -> NSMenu {
        let m = NSMenu()
        m.delegate = self
        m.addItem(submenu("Group By", symbol: "list.bullet.indent", AppSettings.GroupBy.allCases.map { ($0.rawValue, #selector(pickGroup(_:))) }))
        m.addItem(submenu("Sort By", symbol: "arrow.up.arrow.down", AppSettings.SortKey.allCases.map { ($0.rawValue, #selector(pickSort(_:))) }))
        m.addItem(.separator())
        m.addItem(item("Show Local Network", symbol: "desktopcomputer", #selector(toggleLocal)))
        m.addItem(item("Show Network Extensions", symbol: "puzzlepiece.extension", #selector(toggleExtensions)))
        m.addItem(item("Show Connections of Other Users", symbol: "person", #selector(toggleOtherUsers)))
        m.addItem(.separator())
        m.addItem(item("Float on Top", symbol: "macwindow.on.rectangle", #selector(toggleFloat)))
        refresh(m)
        return m
    }

    private func item(_ title: String, symbol: String? = nil, _ action: Selector) -> NSMenuItem {
        let i = NSMenuItem(title: title, action: action, keyEquivalent: "")
        i.target = self
        if let symbol { i.image = NSImage(systemSymbolName: symbol, accessibilityDescription: nil) }
        return i
    }

    private func submenu(_ title: String, symbol: String, _ choices: [(String, Selector)]) -> NSMenuItem {
        let i = NSMenuItem(title: title, action: nil, keyEquivalent: "")
        i.image = NSImage(systemSymbolName: symbol, accessibilityDescription: nil)
        let sub = NSMenu(title: title)
        sub.delegate = self
        for (name, action) in choices { sub.addItem(item(name, action)) }
        i.submenu = sub
        return i
    }

    /// The checkmarks, from the settings: read each time a menu opens, never while it is open.
    func menuNeedsUpdate(_ menu: NSMenu) { refresh(self.menu) }

    func refresh(_ m: NSMenu) {
        for i in m.items {
            switch i.title {
            case "Group By": i.submenu?.items.forEach { $0.state = $0.title == settings.groupBy.rawValue ? .on : .off }
            case "Sort By": i.submenu?.items.forEach { $0.state = $0.title == settings.sortKey.rawValue ? .on : .off }
            case "Show Local Network": i.state = settings.includeLocalNetwork ? .on : .off
            case "Show Network Extensions": i.state = settings.includeNetworkExtensions ? .on : .off
            case "Show Connections of Other Users": i.state = settings.includeOtherUsers ? .on : .off
            case "Float on Top": i.state = settings.floatOnTop ? .on : .off
            default: break
            }
        }
    }

    @objc func pickGroup(_ sender: NSMenuItem) { if let g = AppSettings.GroupBy(rawValue: sender.title) { settings.groupBy = g } }
    @objc func pickSort(_ sender: NSMenuItem) { if let k = AppSettings.SortKey(rawValue: sender.title) { settings.sortKey = k } }
    @objc func toggleLocal() { settings.includeLocalNetwork.toggle() }
    @objc func toggleExtensions() { settings.includeNetworkExtensions.toggle() }
    @objc func toggleOtherUsers() { settings.includeOtherUsers.toggle() }
    @objc func toggleFloat() { settings.floatOnTop.toggle() }
}

/// The chevron that opens a row, as a button so it is reachable by keyboard and UI tests.
struct Disclosure: View {
    let open: Bool
    let label: String
    let toggle: () -> Void
    var body: some View {
        Button(action: toggle) {
            Image(systemName: "chevron.right").font(.caption2).rotationEffect(.degrees(open ? 90 : 0)).foregroundStyle(.secondary)
                .frame(width: 14, height: 14).contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .accessibilityLabel(open ? "Collapse \(label)" : "Expand \(label)")
        .accessibilityIdentifier("disclose-\(label)")
    }
}

/// Mirrored traffic chart: sent above the axis, received below. Bars tile the whole time window.
struct TrafficChart: View {
    @EnvironmentObject var ledger: Ledger
    let range: TimeRange

    var body: some View {
        chart(ledger.chartLayout(range))
            .frame(height: 100)
            .padding(6)
            .background(.black.opacity(0.25), in: RoundedRectangle(cornerRadius: 10))
    }

    // Quiet buckets still draw a dim tick so the chart reads as filled across its whole width.
    @ChartContentBuilder private func sent(_ b: ChartBar, peak: Double) -> some ChartContent {
        RectangleMark(xStart: .value("from", b.start), xEnd: .value("to", b.end), yStart: .value("zero", 0.0), yEnd: .value("sent", max(b.tx, peak * 0.03)))
            .foregroundStyle(b.tx > 0 ? Color.purple : Color.white.opacity(0.18))
    }

    @ChartContentBuilder private func received(_ b: ChartBar, peak: Double) -> some ChartContent {
        RectangleMark(xStart: .value("from", b.start), xEnd: .value("to", b.end), yStart: .value("zero", 0.0), yEnd: .value("received", -max(b.rx, peak * 0.03)))
            .foregroundStyle(b.rx > 0 ? Color.blue : Color.white.opacity(0.18))
    }

    private func chart(_ l: ChartLayout) -> some View {
        Chart(l.bars) { b in
            sent(b, peak: l.peak)
            received(b, peak: l.peak)
        }
        .chartYAxis(.hidden)
        .chartXScale(domain: l.start...l.end)
        .chartYScale(domain: (-l.peak)...l.peak)
        .chartXAxis {
            AxisMarks(values: .automatic(desiredCount: 4)) { _ in
                AxisGridLine().foregroundStyle(Color.white.opacity(0.1))
                AxisValueLabel(format: l.labelFormat).foregroundStyle(Color.white.opacity(0.7))
            }
        }
    }
}
