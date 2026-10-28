import SwiftUI

struct InspectorView: View {
    @EnvironmentObject var ledger: Ledger
    let selection: MonitorSelection?
    /// The list's search and chips: the Summary counts what they leave.
    var filter = MonitorFilter()

    var body: some View {
        ScrollView {
            if let s = selection, let app = ledger.apps.first(where: { $0.id == s.appID }) {
                if let id = s.remote, let r = app.remotes.first(where: { $0.id == id }) {
                    RemoteInspector(app: app, remote: r)
                } else {
                    ProcessInspector(app: app, process: s.process)
                }
            } else {
                SummaryInspector(filter: filter)
            }
        }
        .padding(14)
    }
}

struct SummaryInspector: View {
    @EnvironmentObject var ledger: Ledger
    var filter = MonitorFilter()
    @State private var conns = true
    @State private var stats = true

    var body: some View {
        let s = ledger.summary(filter)
        let domains = ledger.domains(s.remotes), networks = ledger.networks(s.remotes)
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Image(systemName: "list.bullet.rectangle").font(.title2).foregroundStyle(.secondary)
                VStack(alignment: .leading) {
                    Text("Summary").font(.title2.weight(.bold))
                    Text("\(s.apps.count) process\(s.apps.count == 1 ? "" : "es"), \(domains.count) domain\(domains.count == 1 ? "" : "s")").font(.callout).foregroundStyle(.secondary)
                        .accessibilityIdentifier("summary-counts")
                }
            }
            if s.filtered {
                Label("Filtered: the listed apps and their matching connections", systemImage: "line.3.horizontal.decrease.circle")
                    .font(.caption).foregroundStyle(Color.accentColor)
                    .accessibilityIdentifier("summary-filtered")
            }
            HStack(spacing: 8) { Pill(kind: .up, text: formatBytes(s.bytesOut)); Pill(kind: .down, text: formatBytes(s.bytesIn)) }
            SectionHeader(title: "Connections", open: $conns)
            if conns {
                stat("xmark.rectangle", "\(s.denied) denied")
                stat("questionmark.square", "\(s.unconfirmed) unconfirmed")
                stat("arrow.down.left.circle", "\(s.incoming) incoming")
            }
            SectionHeader(title: "Statistics", open: $stats)
            if stats {
                group("Top Processes", s.topApps.map { ($0.identity.name, "\(formatBytes($0.totalIn)) down, \(formatBytes($0.totalOut)) up") })
                group("Top Domains", domains.prefix(3).map { ($0.name, Self.connections($0.count)) })
                if ledger.geo.available {
                    let flags = Dictionary(s.remotes.compactMap { $0.geo.map { ($0.country, $0.flag) } }, uniquingKeysWith: { a, _ in a })
                    group("Top Countries", ledger.countries(s.remotes).prefix(3).map { c in
                        ([flags[c.name] ?? "", c.name].filter { !$0.isEmpty }.joined(separator: " "), Self.connections(c.count))
                    })
                }
                if ledger.geo.networksAvailable, !networks.isEmpty {
                    group("Top Networks", networks.prefix(3).map { ($0.name, Self.connections($0.count)) })
                }
            }
        }
    }

    private static func connections(_ n: Int) -> String { "\(n) connection\(n == 1 ? "" : "s")" }

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
    let app: AppEntry
    /// One of the app's processes (a helper), or nil for the whole app.
    var process: String? = nil
    @State private var proc = true
    @State private var rules = true
    @State private var sig = false
    @State private var details = false
    @State private var geo = false

    private var stats: ProcessStats? { process.flatMap { app.processes[$0] } }
    private var remotes: [RemoteHost] { app.remotes(for: process.map { MonitorSelection(appID: app.id, process: $0) }) }

    var body: some View {
        let (ident, team) = app.identity.signing()
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 10) {
                Image(nsImage: app.identity.icon).resizable().frame(width: 40, height: 40)
                VStack(alignment: .leading, spacing: 0) {
                    Text(process ?? app.identity.name).font(.title2.weight(.bold)).lineLimit(2)
                    if process != nil { Text("Process of \(app.identity.name)").font(.callout).foregroundStyle(.secondary) }
                }
            }
            .accessibilityElement(children: .combine)
            .accessibilityIdentifier("inspector-title")
            HStack(spacing: 8) {
                Pill(kind: .up, text: formatBytes(process == nil ? app.totalOut : stats?.totalOut ?? 0))
                Pill(kind: .down, text: formatBytes(process == nil ? app.totalIn : stats?.totalIn ?? 0))
            }

            SectionHeader(title: "Process", open: $proc)
            if proc {
                if let process {
                    kv("Path", stats?.path ?? process)
                    kv("PIDs", (stats?.pids ?? []).sorted().map(String.init).joined(separator: ", ").nilIfEmpty ?? "not running")
                } else {
                    kv("Path", app.identity.bundlePath ?? app.identity.id)
                    kv("Code ID", [team, ident].compactMap { $0 }.joined(separator: "/").nilIfEmpty ?? "unsigned")
                    kv("User", NSUserName())
                    kv("PIDs", app.pids.sorted().map(String.init).joined(separator: ", "))
                    let others = app.processes.keys.filter { $0 != app.mainProcess }.sorted()
                    if !others.isEmpty, app.identity.bundlePath != nil { kv("Helpers", others.joined(separator: ", ")) }
                    if let by = app.launchedBy {
                        kv("Started by", by)
                        Text("Rules for this tool are its own: allowing or denying \(by.components(separatedBy: " (pid").first ?? by) does not cover it.")
                            .font(.caption).foregroundStyle(.secondary).padding(.leading, 6).fixedSize(horizontal: false, vertical: true)
                    }
                }
            }
            SectionHeader(title: "Rules", open: $rules)
            if rules {
                TargetRules(app: app, target: app.ruleTarget(process: process), service: process)
                // Rules from alerts and the Rules window yield to the process list's ✗/✓ (`RuleEngine.decide`).
                let fromAlerts = ledger.rules.rules(for: app.identity.ruleKey).filter { $0.effectiveListLevel == nil }
                if process == nil, ledger.rules.policy(for: app.identity.ruleKey) == .deny, fromAlerts.contains(where: { $0.verdict == .allow }) {
                    Text("The allow rules above are overridden while the whole app is denied.")
                        .font(.caption).foregroundStyle(.secondary).padding(.leading, 6)
                }
                if process == nil, ledger.rules.policy(for: app.identity.ruleKey) == .allow, fromAlerts.contains(where: { $0.verdict == .deny }) {
                    Text("The deny rules above are overridden while the whole app is allowed.")
                        .font(.caption).foregroundStyle(.secondary).padding(.leading, 6)
                }
                if ledger.rules.policy(for: app.identity.ruleKey) == .deny {
                    Group {
                        if !ledger.enforcer.helperInstalled {
                            Text("Not enforced: this needs the firewall helper (Settings > Security).").foregroundStyle(.orange)
                        } else if ledger.enforcer.status == nil {
                            Text("Not enforced: the firewall helper is not running (Settings > Security).").foregroundStyle(.orange)
                        } else if ledger.enforcer.helperOutdated {
                            Text("May not be enforced: the firewall helper needs an update (Settings > Security).").foregroundStyle(.orange)
                        } else if let e = ledger.enforcement(for: app.id) {
                            Text("Blocked by the firewall helper: \(e.processes) processes, \(e.ports) open connections cut.").foregroundStyle(.secondary)
                        } else {
                            Text("Blocked by the firewall helper as soon as the app runs.").foregroundStyle(.secondary)
                        }
                    }.font(.caption).padding(.leading, 6)
                }
                if let err = ledger.enforcer.lastError { Text(err).font(.caption).foregroundStyle(.red).padding(.leading, 6) }
            }
            SectionHeader(title: "Code Signature", open: $sig)
            if sig { kv("Identifier", ident ?? "none"); kv("Team", team ?? "none") }
            SectionHeader(title: "Connection Details", open: $details)
            if details {
                if app.identity.isSystem && process == nil {
                    // The "macOS" row holds many services: grouped by service, never attributed to a guessed app.
                    let groups = Dictionary(grouping: Array(app.remotes.prefix(80)), by: { $0.process ?? "unknown" }).sorted { $0.key < $1.key }
                    ForEach(groups, id: \.key) { name, list in
                        VStack(alignment: .leading, spacing: 3) {
                            HStack(spacing: 6) {
                                Text(name).font(.callout.weight(.semibold))
                                if let pid = list.first?.pid { Text("pid \(pid)").font(.caption).foregroundStyle(.secondary) }
                            }
                            if let note = SharedServices.note(for: name) {
                                Text("Works for other apps: \(note)").font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                            }
                            ForEach(list) { RemoteSummary(remote: $0, showProcess: false) }
                        }.padding(.leading, 6).padding(.bottom, 4)
                    }
                } else {
                    if let process, let note = SharedServices.note(for: process) {
                        Text("Works for other apps: \(note)").font(.caption).foregroundStyle(.secondary).padding(.leading, 6).fixedSize(horizontal: false, vertical: true)
                    }
                    ForEach(remotes.prefix(50)) { r in
                        RemoteSummary(remote: r, showProcess: process == nil && r.process != nil && r.process != app.mainProcess).padding(.leading, 6)
                    }
                }
                if remotes.isEmpty { Text("None").foregroundStyle(.secondary).padding(.leading, 6) }
            }
            SectionHeader(title: "Geographic Information", open: $geo)
            if geo {
                // Sorted by place, not by flag.
                let places = Set(remotes.flatMap { [$0.geo, $0.via?.serverGeo] }.compactMap { $0 })
                    .sorted { ($0.city, $0.country) < ($1.city, $1.country) }.map(\.place).removingDuplicates()
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

/// One remote: the destination, then protocol, address, port and usual service, then the hops (subprocess, proxy).
struct RemoteSummary: View {
    let remote: RemoteHost
    var showProcess = true

    var body: some View {
        let r = remote
        VStack(alignment: .leading, spacing: 0) {
            Text(r.host).lineLimit(1)
            if let via = r.via {
                // The real destination first, then the proxy hop it went through.
                Text((r.address.isEmpty || r.address == r.host ? "\(r.proto) port \(r.port)" : "\(r.proto) \(r.address):\(r.port)") + serviceSuffix(proto: r.proto, port: r.port))
                    .font(.caption).foregroundStyle(.secondary).help(Self.serviceHelp)
                ProxyBadge(hop: via)
            } else {
                Text("\(r.proto) \(r.address):\(r.port)" + serviceSuffix(proto: r.proto, port: r.port)).font(.caption).foregroundStyle(.secondary).help(Self.serviceHelp)
            }
            if let route = r.route {
                HStack(spacing: 4) {
                    RouteBadges(remote: RemoteHost(address: r.address, host: r.host, port: r.port, proto: r.proto, route: route))
                    Text(route.label).font(.caption2).foregroundStyle(.secondary).lineLimit(1).truncationMode(.middle)
                }
            }
            if let n = r.network {
                Text(n).font(.caption2).foregroundStyle(.secondary).lineLimit(1)
                    .help("The organization that runs this server's network (often a cloud or hosting provider), not necessarily who runs the service.")
            }
            if showProcess, let p = r.process {
                Text("via \(p)\(r.pid.map { " (pid \($0))" } ?? "")").font(.caption2).foregroundStyle(.secondary)
            }
        }
    }

    static let serviceHelp = "The name is the service usually on this port. The port alone does not prove what the connection carries."
}

/// One connection: where it goes, how (process, VPN, proxy), who runs the network, where the server is, and how
/// much it carried.
struct RemoteInspector: View {
    @EnvironmentObject var ledger: Ledger
    let app: AppEntry
    let remote: RemoteHost
    @State private var rules = true

    var body: some View {
        let r = remote
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 10) {
                Image(nsImage: app.identity.icon).resizable().frame(width: 40, height: 40)
                VStack(alignment: .leading, spacing: 0) {
                    Text(r.host).font(.title2.weight(.bold)).lineLimit(2).truncationMode(.middle)
                    Text([app.identity.name, r.process].compactMap { $0 }.removingDuplicates().joined(separator: " › ")).font(.callout).foregroundStyle(.secondary)
                }
            }
            .accessibilityElement(children: .combine)
            .accessibilityIdentifier("inspector-title")
            RouteBadges(remote: r)
            HStack(spacing: 8) { Pill(kind: .up, text: formatBytes(r.bytesOut)); Pill(kind: .down, text: formatBytes(r.bytesIn)) }
            Text("Bytes of the connections open now.").font(.caption).foregroundStyle(.secondary)
            VStack(alignment: .leading, spacing: 6) {
                kv("Address", r.address.isEmpty ? "not looked up" : r.address)
                kv("Port", "\(r.proto) \(r.port)" + (r.incoming ? " on this Mac" : "") + serviceSuffix(proto: r.proto, port: r.port))
                kv("Direction", r.incoming ? "Incoming: the peer connected to this Mac" : r.stream ? "Outgoing, mostly receiving for a while" : "Outgoing")
                if let p = r.process { kv("Process", p + (r.pid.map { " (pid \($0))" } ?? "")) }
                if let n = r.network { kv("Network", n) }
                if let g = r.geo { kv("Location", g.place) }
                if let route = r.route { kv("Route", route.label) }
                if let via = r.via {
                    kv("Proxy", via.label)
                    if let g = via.serverGeo { kv("Proxy at", g.place) }
                }
            }
            SectionHeader(title: "Rules", open: $rules)
            if rules { TargetRules(app: app, target: app.ruleTarget(process: r.process, remote: r), service: r.process, incoming: r.incoming) }
        }
    }

    private func kv(_ k: String, _ v: String) -> some View {
        HStack(alignment: .top) {
            Text(k + ":").foregroundStyle(.secondary).frame(width: 64, alignment: .trailing)
            Text(v).textSelection(.enabled)
        }.font(.callout)
    }
}

/// The Rules section for the selected row (an app, one of its processes, one connection): its own ✗/✓, the rules
/// about it, and Manage Rules…, which opens the Rules window on those rules.
struct TargetRules: View {
    @EnvironmentObject var ledger: Ledger
    @Environment(\.openWindow) private var openWindow
    let app: AppEntry
    /// Nil for a connection no rule can name (inside the local network).
    let target: RulesModel.Target?
    /// The process, for services that work for every app (no one-click Deny).
    var service: String? = nil
    /// A connection a peer started (no rule names it).
    var incoming = false

    private var subject: String {
        switch target?.level { case .connection?: "this connection"; case .process?: "this process"; default: "this app" }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            if let target {
                let p = ledger.rules.rowPolicy(target)
                let shared = app.identity.isSystem && (target.level == .app || service.flatMap(SharedServices.note(for:)) != nil)
                HStack {
                    Text(subject.prefix(1).uppercased() + subject.dropFirst()).font(.callout)
                    Spacer()
                    if shared && p.own == nil {
                        Image(systemName: "lock.fill").foregroundStyle(.secondary)
                            .help("Works for every app: denying it would cut them all. Use a rule for one service in the Rules window.")
                    } else {
                        PolicyToggle(policy: p.own, inherited: p.inherited, subject: subject) { ledger.setPolicy($0, for: target) }
                    }
                }
                .accessibilityElement(children: .contain)
                .accessibilityIdentifier("inspector-policy")
                if p.own == nil, let inherited = p.inherited {
                    Text("Follows the \(target.level == .connection ? "process" : "app")’s \(inherited == .deny ? "Deny" : "Allow"); ✗ or ✓ here makes an exception.")
                        .font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                }
                let signing = app.identity.signing()
                let list = ledger.rules.rules(for: target, signing: (signing.identifier, signing.team))
                let decides = ledger.rules.decidingRule(for: target, signing: (signing.identifier, signing.team))?.id
                VStack(alignment: .leading, spacing: 4) {
                    if list.isEmpty { Text("No rules for \(subject)").foregroundStyle(.secondary) }
                    ForEach(list.prefix(8)) { r in
                        HStack(spacing: 6) {
                            Image(systemName: r.verdict == .deny ? "xmark.circle.fill" : "checkmark.circle.fill").foregroundStyle(r.verdict == .deny ? .red : .green)
                            Text(r.summary).lineLimit(1).truncationMode(.middle).opacity(r.enabled ? 1 : 0.5)
                            if !r.approved { Circle().fill(.blue).frame(width: 7, height: 7) }
                            if r.id == decides { Text("decides").font(.caption2).foregroundStyle(.secondary) }
                        }
                    }
                    if list.count > 8 { Text("and \(list.count - 8) more").font(.caption).foregroundStyle(.secondary) }
                }
                .font(.callout)
                .accessibilityElement(children: .combine)
                .accessibilityIdentifier("inspector-rules")
                .accessibilityValue("\(list.count)")
            } else {
                Text(incoming ? "A peer started this connection. Rules decide what this Mac connects to, so none names it; the app's ✗ still cuts it."
                              : "No rule can name this connection: it stays inside the local network.")
                    .font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            }
            Button("Manage Rules…") { ledger.rules.focus = target ?? RulesModel.Target(app: app.identity.ruleKey); openWindow(id: "rules") }
                .accessibilityIdentifier("manage-rules")
        }
        .padding(.leading, 6)
    }
}

/// "via ssh proxy (127.0.0.1:1080 → 203.0.113.5)" under a destination that went through a local proxy.
struct ProxyBadge: View {
    let hop: ProxyHop
    var body: some View {
        HStack(spacing: 4) {
            Image(systemName: "arrow.triangle.branch")
            Text(hop.label).lineLimit(1).truncationMode(.middle)
            Text(hop.kind).padding(.horizontal, 4).padding(.vertical, 1).overlay(RoundedRectangle(cornerRadius: 3).stroke(.secondary))
        }
        .font(.caption2).foregroundStyle(.orange)
        .help("\(hop.label), \(hop.kind)\(hop.serverGeo.map { ". Proxy server in \($0.place)" } ?? "")")
    }
}

private extension String { var nilIfEmpty: String? { isEmpty ? nil : self } }

private extension Array where Element: Hashable {
    func removingDuplicates() -> [Element] { var seen = Set<Element>(); return filter { seen.insert($0).inserted } }
}
