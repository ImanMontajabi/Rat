import SwiftUI
import Charts
import AppKit

enum SortKey: String, CaseIterable { case name = "Name", traffic = "Traffic", recent = "Recent Activity" }

struct SidebarView: View {
    @EnvironmentObject var ledger: Ledger
    @Environment(\.openWindow) private var openWindow
    @Binding var selection: String?
    @Binding var showChart: Bool
    @Binding var showInspector: Bool

    @State private var search = ""
    @State private var onlyIncoming = false
    @State private var onlyDenied = false
    @State private var sort: SortKey = .recent
    @State private var showLocal = false
    @State private var floatOnTop = false
    @State private var range: TimeRange = .week

    private var rows: [AppEntry] {
        let cutoff = Date().addingTimeInterval(-range.seconds)
        var list = ledger.apps.filter { $0.lastActive >= cutoff && ($0.totalIn + $0.totalOut > 0 || !$0.remotes.isEmpty || $0.listening > 0) }
        if !showLocal { list = list.filter { $0.remotes.isEmpty || $0.remotes.contains { !isLocalAddress($0.address) } || $0.totalIn + $0.totalOut > 0 } }
        if onlyIncoming { list = list.filter { $0.listening > 0 } }
        if onlyDenied { list = list.filter { ledger.rules.policy(for: $0.id) == .deny } }
        if !search.isEmpty {
            list = list.filter { a in
                a.identity.name.localizedCaseInsensitiveContains(search) ||
                a.remotes.contains { $0.host.localizedCaseInsensitiveContains(search) || ($0.geo?.country.localizedCaseInsensitiveContains(search) ?? false) || ($0.geo?.city.localizedCaseInsensitiveContains(search) ?? false) }
            }
        }
        switch sort {
        case .name: return list.sorted { $0.identity.name.localizedCaseInsensitiveCompare($1.identity.name) == .orderedAscending }
        case .traffic: return list.sorted { $0.totalIn + $0.totalOut > $1.totalIn + $1.totalOut }
        case .recent: return list.sorted { ($0.lastActive, $1.identity.name) > ($1.lastActive, $0.identity.name) }
        }
    }

    var body: some View {
        VStack(spacing: 0) {
            toolbar
            searchField
            ScrollView {
                LazyVStack(spacing: 0) {
                    ForEach(rows) { app in
                        ProcessRow(app: app, selected: selection == app.id)
                            .onTapGesture { selection = selection == app.id ? nil : app.id }
                    }
                }
                .padding(.horizontal, 8)
            }
            footer
        }
        .background(.ultraThinMaterial)
    }

    private var toolbar: some View {
        HStack(spacing: 14) {
            ProfileMenu().padding(.leading, 64)   // clear of the window's traffic-light buttons
            Spacer()
            Button { openWindow(id: "rules") } label: {
                Image(systemName: "list.bullet.rectangle")
                    .overlay(alignment: .topTrailing) { if ledger.rules.unapprovedCount > 0 { Circle().fill(.blue).frame(width: 8, height: 8).offset(x: 4, y: -3) } }
            }.help("Rules & Profiles")
            Menu {
                Picker("Sort By", selection: $sort) { ForEach(SortKey.allCases, id: \.self) { Text($0.rawValue).tag($0) } }
                Divider()
                Toggle(isOn: $showLocal) { Label("Show Local Network", systemImage: "desktopcomputer") }
                Toggle(isOn: $floatOnTop) { Label("Float on Top", systemImage: "macwindow.on.rectangle") }
                    .onChange(of: floatOnTop) { _, on in NSApp.windows.first?.level = on ? .floating : .normal }
            } label: { Image(systemName: "line.3.horizontal.decrease") }
            .menuStyle(.borderlessButton).menuIndicator(.hidden).fixedSize()
            Button { showChart.toggle() } label: { Image(systemName: "chart.bar") }.help(showChart ? "Hide Traffic Chart" : "Show Traffic Chart")
            Button { showInspector.toggle() } label: { Image(systemName: "info.circle") }.help(showInspector ? "Hide Inspector" : "Show Inspector")
        }
        .buttonStyle(.plain).font(.system(size: 15))
        .padding(.top, 14).padding(.horizontal, 18).padding(.bottom, 6)
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
            if ledger.enforcer.helperInstalled && ledger.enforcer.autoApply {
                if !ledger.wantedBlocklist.isEmpty {
                    Label("Blocking \(ledger.wantedBlocklist.count) addresses automatically", systemImage: "shield.checkered").font(.caption).foregroundStyle(.secondary)
                }
            } else if ledger.enforcer.needsApply(for: ledger.wantedBlocklist) {
                Button { ledger.applyBlocking() } label: {
                    Label(ledger.enforcer.busy ? "Applying…" : "Apply blocking (\(ledger.wantedBlocklist.count) addresses)", systemImage: "shield.lefthalf.filled")
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.borderedProminent).disabled(ledger.enforcer.busy)
            }
            HStack {
                Text("Session totals").font(.caption).foregroundStyle(.secondary)
                Spacer()
                Text("\(rows.count) apps").font(.caption).foregroundStyle(.secondary)
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
                Spacer(minLength: 4)
                Sparkline(rates: app.rates)
                PolicyToggle(policy: ledger.rules.policy(for: app.id)) { ledger.setPolicy($0, for: app.id) }
            }
            .padding(.vertical, 7).padding(.horizontal, 6)
            .background(selected ? Color.accentColor : .clear, in: RoundedRectangle(cornerRadius: 8))
            if open {
                VStack(alignment: .leading, spacing: 3) {
                    if app.remotes.isEmpty { Text("No outgoing connections").foregroundStyle(.secondary) }
                    ForEach(app.remotes.prefix(30)) { r in
                        HStack {
                            Text(r.host).lineLimit(1)
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

struct TrafficChart: View {
    @EnvironmentObject var ledger: Ledger
    let range: TimeRange
    var body: some View {
        let cutoff = Date().addingTimeInterval(-range.seconds)
        let pts = ledger.chartPoints(range)
        Chart {
            ForEach(pts) { p in
                BarMark(x: .value("t", p.date), y: .value("out", p.tx)).foregroundStyle(.purple)
                BarMark(x: .value("t", p.date), y: .value("in", -p.rx)).foregroundStyle(.blue)
            }
        }
        .chartYAxis(.hidden)
        .chartXScale(domain: cutoff...Date())
        .frame(height: 90)
        .padding(6)
        .background(.black.opacity(0.25), in: RoundedRectangle(cornerRadius: 10))
    }
}
