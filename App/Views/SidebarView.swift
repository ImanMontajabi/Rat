import SwiftUI
import Charts
import AppKit

/// The Network Monitor's left pane. Layout follows Little Snitch's: a row of three icon buttons (filter menu,
/// traffic chart, inspector), a search field with chips and a time-range menu, the process list, and at the
/// bottom the sent / received pills over the traffic chart.
struct SidebarView: View {
    @EnvironmentObject var ledger: Ledger
    @ObservedObject private var settings = AppSettings.shared
    @Binding var selection: String?
    @Binding var showChart: Bool
    @Binding var showInspector: Bool

    @State private var search = ""
    @State private var onlyIncoming = false
    @State private var onlyDenied = false
    @State private var range: TimeRange = .fiveMinutes
    @State private var expandedGroups = Set<String>()

    // MARK: data

    private var cutoff: Date { Date().addingTimeInterval(-range.seconds) }

    private var filtered: [AppEntry] {
        var list = ledger.apps.filter { $0.lastActive >= cutoff && ($0.totalIn + $0.totalOut > 0 || !$0.remotes.isEmpty || $0.listening > 0) }
        if !settings.includeLocalNetwork {
            list = list.filter { $0.remotes.isEmpty || $0.remotes.contains { !isLocalAddress($0.address) } || $0.totalIn + $0.totalOut > 0 }
        }
        if !settings.includeNetworkExtensions { list = list.filter { !$0.identity.isExtension } }
        if !settings.includeOtherUsers { list = list.filter { !$0.otherUsers } }
        if onlyIncoming { list = list.filter { $0.listening > 0 } }
        if onlyDenied { list = list.filter { ledger.rules.policy(for: $0.identity.ruleKey) == .deny } }
        if !search.isEmpty {
            list = list.filter { a in
                a.identity.name.localizedCaseInsensitiveContains(search) ||
                a.remotes.contains { $0.host.localizedCaseInsensitiveContains(search) || ($0.geo?.country.localizedCaseInsensitiveContains(search) ?? false) || ($0.geo?.city.localizedCaseInsensitiveContains(search) ?? false) }
            }
        }
        return list
    }

    private var rows: [AppEntry] {
        let list = filtered
        switch settings.sortKey {
        case .name: return list.sorted { $0.identity.name.localizedCaseInsensitiveCompare($1.identity.name) == .orderedAscending }
        case .traffic: return list.sorted { $0.totalIn + $0.totalOut > $1.totalIn + $1.totalOut }
        case .recent: return list.sorted { ($0.lastActive, $1.identity.name) > ($1.lastActive, $0.identity.name) }
        }
    }

    private struct Group: Identifiable { let id: String; let title: String; let apps: [AppEntry] }

    private var groups: [Group] {
        var d: [String: [AppEntry]] = [:]
        for a in filtered {
            let keys: Set<String>
            switch settings.groupBy {
            case .domain: keys = Set(a.remotes.filter { !isLocalAddress($0.address) }.map { registrableDomain($0.host) })
            case .country: keys = Set(a.remotes.compactMap { $0.geo?.country })
            case .process: keys = []
            }
            for k in keys { d[k, default: []].append(a) }
        }
        return d.map { Group(id: $0.key, title: $0.key, apps: $0.value) }.sorted { $0.apps.count > $1.apps.count }
    }

    // MARK: body

    var body: some View {
        VStack(spacing: 0) {
            toolbar
            searchField
            ScrollView {
                LazyVStack(spacing: 0) {
                    if settings.groupBy == .process {
                        ForEach(rows) { app in
                            ProcessRow(app: app, selected: selection == app.id)
                                .onTapGesture { selection = selection == app.id ? nil : app.id }
                        }
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
                Text("\(g.apps.count)").font(.caption).foregroundStyle(.secondary)
            }
            .padding(.vertical, 8).padding(.horizontal, 6).contentShape(Rectangle())
            .onTapGesture { if !expandedGroups.insert(g.id).inserted { expandedGroups.remove(g.id) } }
            if expandedGroups.contains(g.id) {
                ForEach(g.apps) { app in
                    ProcessRow(app: app, selected: selection == app.id).padding(.leading, 18)
                        .onTapGesture { selection = selection == app.id ? nil : app.id }
                }
            }
        }
    }

    /// Three icon buttons, in the reference order: filter menu, traffic chart, inspector.
    private var toolbar: some View {
        HStack(spacing: 16) {
            Spacer()
            Menu {
                Menu {
                    Picker("Group By", selection: $settings.groupBy) { ForEach(AppSettings.GroupBy.allCases) { Text($0.rawValue).tag($0) } }.pickerStyle(.inline)
                } label: { Label("Group By", systemImage: "list.bullet.indent") }
                Menu {
                    Picker("Sort By", selection: $settings.sortKey) { ForEach(AppSettings.SortKey.allCases) { Text($0.rawValue).tag($0) } }.pickerStyle(.inline)
                } label: { Label("Sort By", systemImage: "arrow.up.arrow.down") }
                Divider()
                Toggle(isOn: $settings.includeLocalNetwork) { Label("Show Local Network", systemImage: "desktopcomputer") }
                Toggle(isOn: $settings.includeNetworkExtensions) { Label("Show Network Extensions", systemImage: "puzzlepiece.extension") }
                Toggle(isOn: $settings.includeOtherUsers) { Label("Show Connections of Other Users", systemImage: "person") }
                Divider()
                Toggle(isOn: $settings.floatOnTop) { Label("Float on Top", systemImage: "macwindow.on.rectangle") }
            } label: { Image(systemName: "slider.horizontal.3") }
            .menuStyle(.borderlessButton).menuIndicator(.hidden).fixedSize()
            .help("View options")
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
            TextField("Search", text: $search).textFieldStyle(.plain)
            chip("arrow.down.left.circle", on: $onlyIncoming, help: "Only apps accepting incoming connections")
            chip("xmark.rectangle", on: $onlyDenied, help: "Only denied apps")
            Menu {
                ForEach(TimeRange.allCases) { r in Button(r.title) { range = r } }
            } label: { Label(range.rawValue, systemImage: "clock").font(.callout) }
            .menuStyle(.borderlessButton).fixedSize()
        }
        .padding(.horizontal, 12).padding(.vertical, 8)
        .background(.white.opacity(0.08), in: Capsule())
        .padding(.horizontal, 14).padding(.bottom, 10)
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
            if !ledger.deniedAppPaths.isEmpty {
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
                Text(settings.groupBy == .process ? "\(rows.count) apps" : "\(groups.count) groups").font(.caption).foregroundStyle(.secondary)
                Spacer()
                Text("Last \(range.title)").font(.caption).foregroundStyle(.secondary)
            }
        }
        .padding(10)
    }
}

struct ProcessRow: View {
    @EnvironmentObject var ledger: Ledger
    let app: AppEntry
    let selected: Bool
    @State private var open = false

    var body: some View {
        VStack(spacing: 0) {
            HStack(spacing: 8) {
                Image(systemName: "chevron.right").font(.caption2).rotationEffect(.degrees(open ? 90 : 0)).foregroundStyle(.secondary)
                    .frame(width: 14).contentShape(Rectangle()).onTapGesture { withAnimation(.easeInOut(duration: 0.15)) { open.toggle() } }
                Image(nsImage: app.identity.icon).resizable().frame(width: 24, height: 24)
                Text(app.identity.name).lineLimit(1).font(.system(size: 14, weight: .medium))
                if app.identity.isExtension {
                    Text("EXT").font(.system(size: 9, weight: .semibold)).padding(.horizontal, 4).padding(.vertical, 1)
                        .overlay(RoundedRectangle(cornerRadius: 3).stroke(.secondary)).foregroundStyle(.secondary)
                }
                Spacer(minLength: 4)
                Sparkline(rates: app.rates)
                PolicyToggle(policy: ledger.rules.policy(for: app.identity.ruleKey)) { ledger.setPolicy($0, for: app.id) }
            }
            .padding(.vertical, 7).padding(.horizontal, 6)
            .background(selected ? Color.accentColor : .clear, in: RoundedRectangle(cornerRadius: 8))
            if open {
                VStack(alignment: .leading, spacing: 3) {
                    if app.remotes.isEmpty { Text("No outgoing connections").foregroundStyle(.secondary) }
                    ForEach(app.remotes.prefix(30)) { r in
                        HStack {
                            Text(r.host).lineLimit(1)
                            if let via = r.via {
                                Text("via \(via.process)").foregroundStyle(.orange).lineLimit(1).help(via.label)
                            }
                            Spacer()
                            Text("\(r.proto) \(r.port)").foregroundStyle(.secondary).monospacedDigit()
                        }
                    }
                }
                .font(.caption).padding(.leading, 52).padding(.trailing, 8).padding(.vertical, 4)
            }
        }
        .contentShape(Rectangle())
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
