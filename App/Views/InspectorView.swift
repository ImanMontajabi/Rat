import SwiftUI

struct InspectorView: View {
    @EnvironmentObject var ledger: Ledger
    let selection: String?

    var body: some View {
        ScrollView {
            if let id = selection, let app = ledger.apps.first(where: { $0.id == id }) {
                ProcessInspector(app: app)
            } else {
                SummaryInspector()
            }
        }
        .padding(14)
    }
}

struct SummaryInspector: View {
    @EnvironmentObject var ledger: Ledger
    @State private var conns = true
    @State private var stats = true

    var body: some View {
        let denied = ledger.deniedCount, unconfirmed = ledger.unconfirmedCount, incoming = ledger.incomingCount
        let topApps = ledger.apps.sorted { $0.totalIn + $0.totalOut > $1.totalIn + $1.totalOut }.prefix(3)
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Image(systemName: "list.bullet.rectangle").font(.title2).foregroundStyle(.secondary)
                VStack(alignment: .leading) {
                    Text("Summary").font(.title2.weight(.bold))
                    Text("\(ledger.apps.count) processes, \(ledger.domains().count) domains").font(.callout).foregroundStyle(.secondary)
                }
            }
            HStack(spacing: 8) { Pill(kind: .up, text: formatBytes(ledger.sessionOut)); Pill(kind: .down, text: formatBytes(ledger.sessionIn)) }
            SectionHeader(title: "Connections", open: $conns)
            if conns {
                stat("xmark.rectangle", "\(denied) denied")
                stat("questionmark.square", "\(unconfirmed) unconfirmed")
                stat("arrow.down.left.circle", "\(incoming) incoming")
            }
            SectionHeader(title: "Statistics", open: $stats)
            if stats {
                group("Top Processes", topApps.map { ($0.identity.name, "\(formatBytes($0.totalIn)) down, \(formatBytes($0.totalOut)) up") })
                group("Top Domains", ledger.domains().prefix(3).map { ($0.name, "\($0.count) connection\($0.count == 1 ? "" : "s")") })
                if ledger.geo.available { group("Top Countries", ledger.countries().prefix(3).map { ($0.name, "\($0.count) connection\($0.count == 1 ? "" : "s")") }) }
            }
        }
    }

    private func stat(_ symbol: String, _ text: String) -> some View {
        HStack(spacing: 10) { Image(systemName: symbol).frame(width: 26).foregroundStyle(.secondary); Text(text).font(.title3) }.padding(.leading, 6)
    }

    private func group(_ title: String, _ items: [(String, String)]) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(title).font(.callout).foregroundStyle(.secondary).padding(.top, 6)
            ForEach(Array(items.enumerated()), id: \.offset) { _, it in
                VStack(alignment: .leading, spacing: 0) { Text(it.0).font(.title3); Text(it.1).font(.callout).foregroundStyle(.secondary) }
            }
        }.padding(.leading, 6)
    }
}

struct ProcessInspector: View {
    @EnvironmentObject var ledger: Ledger
    @Environment(\.openWindow) private var openWindow
    let app: AppEntry
    @State private var proc = true
    @State private var rules = true
    @State private var sig = false
    @State private var details = false
    @State private var geo = false

    var body: some View {
        let (ident, team) = app.identity.signing()
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 10) {
                Image(nsImage: app.identity.icon).resizable().frame(width: 40, height: 40)
                Text(app.identity.name).font(.title2.weight(.bold))
            }
            HStack(spacing: 8) { Pill(kind: .up, text: formatBytes(app.totalOut)); Pill(kind: .down, text: formatBytes(app.totalIn)) }

            SectionHeader(title: "Process", open: $proc)
            if proc {
                kv("Path", app.identity.bundlePath ?? app.identity.id)
                kv("Code ID", [team, ident].compactMap { $0 }.joined(separator: "/").nilIfEmpty ?? "unsigned")
                kv("User", NSUserName())
                kv("PIDs", app.pids.sorted().map(String.init).joined(separator: ", "))
            }
            SectionHeader(title: "Rules", open: $rules)
            if rules {
                let appRules = ledger.rules.rules(for: app.identity.ruleKey)
                if appRules.isEmpty { Text("No rules for these connections").foregroundStyle(.secondary).padding(.leading, 6) }
                ForEach(appRules.prefix(8)) { r in
                    HStack(spacing: 6) {
                        Image(systemName: r.verdict == .deny ? "xmark.circle.fill" : "checkmark.circle.fill").foregroundStyle(r.verdict == .deny ? .red : .green)
                        Text(r.summary).lineLimit(1)
                        if !r.approved { Circle().fill(.blue).frame(width: 7, height: 7) }
                    }.font(.callout).padding(.leading, 6)
                }
                if ledger.rules.policy(for: app.identity.ruleKey) == .deny, appRules.contains(where: { $0.verdict == .allow }) {
                    Text("The allow rules above are overridden while the whole app is denied.")
                        .font(.caption).foregroundStyle(.secondary).padding(.leading, 6)
                }
                if ledger.rules.policy(for: app.identity.ruleKey) == .deny {
                    Group {
                        if !ledger.enforcer.helperInstalled {
                            Text("Not enforced: this needs the firewall helper (Settings > Security).").foregroundStyle(.orange)
                        } else if ledger.enforcer.status == nil {
                            Text("Not enforced: the firewall helper is not running (Settings > Security).").foregroundStyle(.orange)
                        } else if let e = ledger.enforcement(for: app.id) {
                            Text("Blocked by the firewall helper: \(e.processes) processes, \(e.ports) open connections cut.").foregroundStyle(.secondary)
                        } else {
                            Text("Blocked by the firewall helper as soon as the app runs.").foregroundStyle(.secondary)
                        }
                    }.font(.caption).padding(.leading, 6)
                }
                Button("Manage Rules…") { openWindow(id: "rules") }.padding(.leading, 6)
                if let err = ledger.enforcer.lastError { Text(err).font(.caption).foregroundStyle(.red).padding(.leading, 6) }
            }
            SectionHeader(title: "Code Signature", open: $sig)
            if sig { kv("Identifier", ident ?? "none"); kv("Team", team ?? "none") }
            SectionHeader(title: "Connection Details", open: $details)
            if details {
                ForEach(app.remotes.prefix(50)) { r in
                    VStack(alignment: .leading, spacing: 0) {
                        Text(r.host).lineLimit(1)
                        Text("\(r.proto) \(r.address):\(r.port)").font(.caption).foregroundStyle(.secondary)
                    }.padding(.leading, 6)
                }
                if app.remotes.isEmpty { Text("None").foregroundStyle(.secondary).padding(.leading, 6) }
            }
            SectionHeader(title: "Geographic Information", open: $geo)
            if geo {
                let places = Set(app.remotes.compactMap { $0.geo }.map { "\($0.city), \($0.country)" }).sorted()
                if places.isEmpty { Text("No locations for these connections").foregroundStyle(.secondary).padding(.leading, 6) }
                ForEach(places, id: \.self) { Text($0).padding(.leading, 6) }
            }
        }
    }

    private func kv(_ k: String, _ v: String) -> some View {
        HStack(alignment: .top) {
            Text(k + ":").foregroundStyle(.secondary).frame(width: 64, alignment: .trailing)
            Text(v).textSelection(.enabled)
        }.font(.callout)
    }
}

private extension String { var nilIfEmpty: String? { isEmpty ? nil : self } }
