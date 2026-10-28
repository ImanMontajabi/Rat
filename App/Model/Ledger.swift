import SwiftUI
import CoreLocation
import RatMonitor
import RatFilterCore
import RatEnforce
import os
import Combine

private let logger = Logger(subsystem: "com.imanmontajabi.Rat", category: "ledger")

enum TimeRange: String, CaseIterable, Identifiable {
    case fiveMinutes = "5m", hour = "1h", day = "1d", week = "1w"
    var id: String { rawValue }
    var seconds: TimeInterval {
        switch self {
        case .fiveMinutes: return 300
        case .hour: return 3600
        case .day: return 86_400
        case .week: return 604_800
        }
    }
    var title: String {
        switch self {
        case .fiveMinutes: return "5 minutes"
        case .hour: return "1 hour"
        case .day: return "1 day"
        case .week: return "1 week"
        }
    }
}

/// What the Summary counts (`Ledger.summary`).
struct MonitorSummary {
    /// A search or chip narrowed it to the listed apps.
    var filtered: Bool
    var apps: [AppEntry]
    var remotes: [RemoteHost]
    /// The session's traffic, or the listed apps' totals.
    var bytesIn: UInt64
    var bytesOut: UInt64
    var denied: Int
    var unconfirmed: Int
    var incoming: Int

    var topApps: [AppEntry] { Array(apps.sorted { ($0.totalIn + $0.totalOut, $1.identity.name) > ($1.totalIn + $1.totalOut, $0.identity.name) }.prefix(3)) }
}

struct RemoteHost: Identifiable, Hashable {
    /// One row per server, port and protocol of a process: a TCP and a UDP (QUIC) connection to one server are two
    /// rows, as a ✗/✓ on either is a rule for its own protocol. Connections a peer started are rows of their own.
    var id: String { (incoming ? "in|" : "") + (via.map { "\(host):\(port) \($0.listener)" } ?? "\(address):\(port)/\(proto)") + "|\(process ?? "")" }
    /// The server's address; for a destination behind a local proxy, the name's address (empty until looked up).
    let address: String
    var host: String
    var port: Int
    var proto: String
    var geo: GeoPoint?
    /// Set when the connection went through a local proxy: `host` is the real destination, `via` the hop.
    var via: ProxyHop? = nil
    /// The process that holds the socket (an app's helper, or the system service in the "macOS" row).
    var pid: Int32? = nil
    var process: String? = nil
    /// Who runs the server's network (`AS13335 Cloudflare, Inc.`), from the offline ASN database.
    var network: String? = nil
    /// VPN tunnel, system proxy or local proxy the connection goes through, when it does.
    var route: RouteTag? = nil
    /// Bytes of the connection's open sockets so far (nettop's per-connection counters; a closed socket drops out).
    var bytesIn: UInt64 = 0
    var bytesOut: UInt64 = 0
    /// What the rules said on the last pass (nil for local addresses, and while the name is still looked up).
    var verdict: Verdict? = nil
    /// A peer started it: `address` is the peer and `port` the port of this Mac it connected to (`SocketDirection`).
    var incoming = false
    /// A long-lived connection that mostly receives: a download, a server push, a media stream (`StreamDetector`).
    var stream = false
}

/// One executable of an app (its main binary, a helper, an XPC service working for it), by name.
struct ProcessStats: Hashable {
    var name: String
    var path: String
    /// Running processes of this executable (Chrome runs many helpers of the same name).
    var pids: Set<Int32> = []
    var totalIn: UInt64 = 0
    var totalOut: UInt64 = 0
}

/// A node under an app's row: one of its processes and the connections it holds.
struct ProcessNode: Identifiable, Hashable {
    var id: String { name }
    var name: String
    var path: String?
    var pids: [Int32]
    var remotes: [RemoteHost]
    var totalIn: UInt64
    var totalOut: UInt64
}

struct AppEntry: Identifiable {
    var identity: AppIdentity
    var id: String { identity.id }
    var pids: Set<Int32> = []
    var remotes: [RemoteHost] = []
    var listening = 0
    var rates: [(rx: Double, tx: Double)] = []
    var totalIn: UInt64 = 0
    var totalOut: UInt64 = 0
    var lastActive = Date.distantPast
    var otherUsers = false
    /// The app's executables seen this session, by name.
    var processes: [String: ProcessStats] = [:]
    /// For a command-line tool: the app that started it ("Warp (pid 812)"). Display only: rules and the helper
    /// still treat the tool as its own app.
    var launchedBy: String? = nil

    /// The executable whose connections sit directly under the app's row. Nil for the macOS row (every service is
    /// its own node) and for command-line tools (one executable: everything is direct).
    @MainActor var mainProcess: String? { identity.isSystem ? nil : (identity.mainProcessName ?? identity.name) }

    /// The app's tree: the main process's connections, then one node per other process that has connections or
    /// traffic. A command-line tool has no sub-processes.
    @MainActor var tree: (direct: [RemoteHost], processes: [ProcessNode]) {
        guard identity.isSystem || identity.bundlePath != nil else { return (remotes, []) }
        let main = mainProcess
        var direct: [RemoteHost] = [], byProcess: [String: [RemoteHost]] = [:]
        for r in remotes {
            let name = r.process ?? main ?? "unknown"
            if name == main { direct.append(r) } else { byProcess[name, default: []].append(r) }
        }
        var names = Set(byProcess.keys)
        for (name, p) in processes where name != main && !p.pids.isEmpty && p.totalIn + p.totalOut > 0 { names.insert(name) }
        let nodes = names.map { name in
            ProcessNode(name: name, path: processes[name]?.path, pids: (processes[name]?.pids ?? Set(byProcess[name]?.compactMap(\.pid) ?? [])).sorted(),
                        remotes: byProcess[name] ?? [], totalIn: processes[name]?.totalIn ?? 0, totalOut: processes[name]?.totalOut ?? 0)
        }
        return (direct, nodes.sorted { ($0.remotes.count, $1.name) > ($1.remotes.count, $0.name) })
    }
}

extension RemoteHost {
    var isVPN: Bool { route?.isVPN ?? false }
    /// Through a local or system proxy: unmasked behind one (`via`), or tagged as talking to one.
    var isProxied: Bool { via != nil || (route?.isProxy ?? false) }
    /// Stays near this Mac (`isLocalTraffic`), so Hide Local leaves it out. A connection through a proxy leaves the
    /// Mac even when its socket goes to 127.0.0.1.
    var isLocal: Bool { !isProxied && isLocalTraffic(address: address, proto: proto, port: port) }
}

extension AppEntry {
    /// Every connection it has stays near this Mac: Hide Local hides it. An app without connections is not.
    var onlyLocal: Bool { !remotes.isEmpty && remotes.allSatisfy(\.isLocal) }
}

extension AppEntry {
    /// The connections a selection covers: the whole app, one process, or one connection.
    @MainActor func remotes(for selection: MonitorSelection?) -> [RemoteHost] {
        guard let selection, selection.appID == id else { return remotes }
        if let r = selection.remote { return remotes.filter { $0.id == r } }
        guard let p = selection.process else { return remotes }
        let main = mainProcess
        return remotes.filter { ($0.process ?? main) == p }
    }

    /// The executable of one of the app's processes (by name; nil = the main process), for rules about it.
    @MainActor func executablePath(of process: String?) -> String? {
        guard let name = process ?? mainProcess else { return nil }
        if let p = processes[name]?.path { return p }
        guard name == mainProcess else { return nil }
        return identity.bundlePath.flatMap { Bundle(path: $0)?.executableURL?.path } ?? (identity.bundlePath == nil ? identity.id : nil)
    }

    /// The row of the process list a selection is, as rules see it. Nil when no rule can name it: an executable
    /// that was never seen, or a connection inside the local network (Rat's pass does not judge those).
    @MainActor func ruleTarget(process: String?, remote: RemoteHost? = nil) -> RulesModel.Target? {
        guard process != nil || remote != nil else { return RulesModel.Target(app: identity.ruleKey) }
        guard let exe = executablePath(of: remote?.process ?? process) else { return nil }
        guard let r = remote else { return RulesModel.Target(app: identity.ruleKey, executable: exe) }
        let e = RulesModel.Endpoint(host: r.host, address: r.address, port: r.port, proto: r.proto == "UDP" ? .udp : .tcp)
        if r.via == nil && (r.address.isEmpty || isLocalAddress(r.address)) { return nil }
        // Rules decide what this Mac connects to; a peer that connected to it is not one of those.
        if r.incoming { return nil }
        if e.name == nil && r.address.isEmpty { return nil }
        return RulesModel.Target(app: identity.ruleKey, executable: exe, endpoint: e)
    }

    @MainActor func ruleTarget(for s: MonitorSelection) -> RulesModel.Target? {
        ruleTarget(process: s.process, remote: s.remote.flatMap { id in remotes.first { $0.id == id } })
    }
}

/// What the monitor shows: an app, one of its processes, or one connection. It scopes the map and the inspector.
struct MonitorSelection: Hashable {
    var appID: String
    var process: String? = nil
    var remote: String? = nil
}

struct ChartBar: Identifiable {
    let start: Date
    let end: Date
    let rx: Double
    let tx: Double
    var id: Date { start }
}

struct ChartLayout {
    var bars: [ChartBar]
    var start: Date
    var end: Date
    var peak: Double
    var labelFormat: Date.FormatStyle
}

struct TrafficPoint: Identifiable {
    let date: Date
    let rx: Double
    let tx: Double
    var id: Date { date }
}

@MainActor
final class Ledger: ObservableObject {
    @Published var apps: [AppEntry] = []
    @Published var history: [TrafficPoint] = []
    @Published var sessionIn: UInt64 = 0
    @Published var sessionOut: UInt64 = 0
    @Published var rateIn = 0.0
    @Published var rateOut = 0.0
    @Published var myLocation: GeoPoint?
    @Published var deniedCount = 0
    @Published var unconfirmedCount = 0
    @Published var incomingCount = 0
    @Published var systemWide = false

    let rules: RulesModel
    let enforcer: Enforcer
    let geo = GeoService()
    /// The database files the user chose in Settings > GeoIP (or the bundled ones).
    let geoDatabases: GeoDatabases
    private(set) lazy var alerts: AlertCenter = {
        let center = AlertCenter(rules: rules) { [unowned self] alert, verdict in
            refreshEnforcement()
        }
        center.isStillPending = { [unowned self] a in
            let c = Connection(process: ProcessIdentity(path: a.appID), executable: a.executable, host: a.host == a.address ? nil : a.host,
                               address: a.address, port: a.port, proto: a.proto == "UDP" ? .udp : .tcp)
            return rules.engine.decide(c).verdict == .ask
        }
        return center
    }()
    var onTick: (() -> Void)?

    private let names: HostNames
    private let store: StateStore
    private var previous: [Int32: TrafficCounter] = [:]
    private var launchers: [Int32: String?] = [:]
    private var table: [String: AppEntry] = [:]
    private var buckets: [Date: Bucket] = [:]
    private var deniedPorts = Set<Int>()
    private var deniedLoopbackPorts = Set<Int>()
    private let proxyResolver = ProxyResolver()
    /// Which sockets are long-lived download streams, by their counters on each pass.
    var streams = StreamDetector()
    let routes = RouteMarker()
    private var signingCache: [String: (identifier: String?, team: String?)] = [:]
    private var rulesChanged: AnyCancellable?
    private var running = false
    private var demo = false
    private var lastSave = Date()
    private var lastTick = Date()
    private var startedAt = Date()

    init(directory: URL? = nil, helperInstalled: Bool? = nil, names: HostNames = HostNames()) {
        self.names = names
        // Demo mode never reads or writes the real data folder, and sees no helper: its files are not the daemon's.
        let demo = directory == nil && Preferences.isDemo
        store = StateStore.standard(base: demo ? FileManager.default.temporaryDirectory.appendingPathComponent("rat-demo-\(UUID())") : directory)
        let helperInstalled = demo ? false : helperInstalled
        rules = RulesModel(directory: store.directory)
        geoDatabases = GeoDatabases(directory: store.directory, geo: geo)
        enforcer = Enforcer(supportDirectory: store.directory, helperInstalled: helperInstalled,
                            statusPath: helperInstalled == nil ? nil : store.directory.appendingPathComponent("enforcer-status.json").path,
                            proxiedPath: helperInstalled == nil ? nil : store.directory.appendingPathComponent("proxied.json").path)
        myLocation = GeoService.localPoint()
        let saved = store.load()
        for a in saved.apps where !a.id.hasPrefix("pid ") {
            // Re-resolve plain executables so names learned by older versions ("2.1.308") are corrected and merged.
            let ident = a.isSystem || a.id.hasSuffix("#ext") ? AppIdentity(id: a.id, name: a.name, bundlePath: a.bundlePath, isSystem: a.isSystem, isExtension: a.id.hasSuffix("#ext"))
                                                             : AppIdentity.resolve(processPath: a.id)
            var e = table[ident.id] ?? AppEntry(identity: ident)
            e.totalIn += a.totalIn; e.totalOut += a.totalOut; e.lastActive = max(e.lastActive, a.lastActive)
            table[ident.id] = e
        }
        for b in saved.buckets { buckets[b.minute] = b }
        apps = Array(table.values)
        alerts.iconProvider = { [weak self] id in self?.table[id]?.identity.icon ?? NSImage() }
        // Views observe the ledger and read rules through it (the policy toggles, the Rules window): a rule change
        // redraws them at once, not on the next sampling pass (which demo mode never has).
        rulesChanged = rules.objectWillChange.sink { [weak self] _ in self?.objectWillChange.send() }
        #if DEBUG
        if demo { installDemoData() }
        #endif
    }

    // MARK: lifecycle

    func start() {
        guard !running else { return }
        running = true
        startedAt = Date()
        logger.notice("ledger started")
        Task { await loop() }
    }

    func save() {
        guard !demo else { return }   // demo data must never reach the real state files
        let weekAgo = Date().addingTimeInterval(-TimeRange.week.seconds)
        let state = PersistedState(
            apps: table.values.map { PersistedApp(id: $0.id, name: $0.identity.name, bundlePath: $0.identity.bundlePath, isSystem: $0.identity.isSystem, totalIn: $0.totalIn, totalOut: $0.totalOut, lastActive: $0.lastActive) },
            buckets: buckets.values.filter { $0.minute > weekAgo }.sorted { $0.minute < $1.minute })
        store.save(state)
        rules.saveNow()
        lastSave = Date()
    }

    /// Re-checks queued alerts against the current rules and mode: answered, allowed or denied apps never prompt.
    func revalidateAlerts() { alerts.revalidate() }

    func shutdown() {
        rules.purgeSessionRules()
        // Rules for this session end with it: the daemon stops following them too.
        enforcer.syncRules(daemonRules)
        save()
    }

    private func loop() async {
        while running && !demo {
            let useSnapshot = enforcer.systemSnapshotText()
            let (conns, traffic) = await Task.detached(priority: .utility) { () -> ([ObservedConnection], TrafficSampler.Sample) in
                var c = ConnectionSampler.sample()
                if let text = useSnapshot {
                    // Root helper snapshot: adds processes this app cannot inspect (other users, system daemons).
                    var seen = Set(c.map { "\($0.pid)|\($0.proto.rawValue)|\($0.localPort)|\($0.remoteAddress)|\($0.remotePort)" })
                    // A process is named by the kernel's path, as the root daemon reads it: `ps` gives the name a
                    // program was started by (a symlink into a cryptex, a bare name), and a rule made from that name
                    // would name a different file than the daemon sees.
                    var kernelPaths: [Int32: String] = [:]
                    for var x in SystemSnapshot.parse(text, listeners: true) where seen.insert("\(x.pid)|\(x.proto.rawValue)|\(x.localPort)|\(x.remoteAddress)|\(x.remotePort)").inserted {
                        let k = kernelPaths[x.pid] ?? ConnectionSampler.path(of: x.pid)
                        kernelPaths[x.pid] = k
                        if !k.hasPrefix("pid ") { x.processPath = k }
                        c.append(x)
                    }
                }
                return (c, TrafficSampler.sampleWithFlows())
            }.value
            systemWide = useSnapshot != nil
            await ingest(conns, traffic.processes, flows: traffic.flows)
            rules.refreshNetwork()
            refreshEnforcement()
            alerts.revalidate()
            onTick?()
            if Date().timeIntervalSince(lastSave) > 30 { save() }
            // A ✗/✓ cuts the nap short (`requestPass`), so open connections are judged by the new rule at once.
            let nap = Task { _ = try? await Task.sleep(for: .seconds(1.5)) }
            napTask = nap
            await nap.value
        }
    }

    private var napTask: Task<Void, Never>?

    /// Runs the next pass now instead of after the rest of the 1.5 s nap.
    func requestPass() { napTask?.cancel() }

    // MARK: sampling

    private func signing(for identity: AppIdentity) -> (identifier: String?, team: String?) {
        if let c = signingCache[identity.id] { return c }
        let s = identity.signing()
        signingCache[identity.id] = s
        return s
    }

    func ingest(_ conns: [ObservedConnection], _ traffic: [TrafficCounter], flows: [FlowCounter] = []) async {
        let now = Date()
        // Which connections a peer started: their local port is a listener's.
        let conns = SocketDirection.mark(conns)
        let dt = max(now.timeIntervalSince(lastTick), 0.2)
        lastTick = now
        let warmedUp = now.timeIntervalSince(startedAt) > 12   // don't alert for sockets that already existed at launch

        var identityByPid: [Int32: AppIdentity] = [:]
        var perApp: [String: (conns: [ObservedConnection], listening: Int)] = [:]
        for c in conns {
            guard !c.processPath.hasPrefix("pid ") else { continue }   // process already gone: nothing to attribute
            let ident = identityByPid[c.pid] ?? AppIdentity.resolve(processPath: c.processPath, pid: c.pid)
            identityByPid[c.pid] = ident
            var e = perApp[ident.id] ?? ([], 0)
            if c.tcpState == "LISTEN" { e.listening += 1 } else if c.isOutbound { e.conns.append(c) }
            perApp[ident.id] = e
            if table[ident.id] == nil { table[ident.id] = AppEntry(identity: ident) }
            table[ident.id]!.pids.insert(c.pid)
            noteProcess(c.pid, path: c.processPath, in: ident)
        }
        let alive = Set(conns.map(\.pid)).union(traffic.map(\.pid))
        // Loopback listeners by port, to tag connections to a local proxy (ssh -D, Tor) that the helper did not unmask.
        var listeners: [Int: (pid: Int32, path: String)] = [:]
        for c in conns where c.proto == .tcp && c.tcpState == "LISTEN" && c.localPort != 0 && listeners[c.localPort] == nil { listeners[c.localPort] = (c.pid, c.processPath) }
        let bytesByFlow = Dictionary(flows.map { ($0.key, ($0.bytesIn, $0.bytesOut)) }, uniquingKeysWith: { a, b in (a.0 + b.0, a.1 + b.1) })

        routes.refresh(now: now, helperTunnels: enforcer.status?.tunnels)
        // Connections through a local proxy: the destination the client asked for replaces its loopback socket.
        let unmasked = ProxyUnmasking.unmask(flows: enforcer.proxiedFlows(), conns: conns, now: now, arguments: { ProcessArguments.read(pid: $0) })
        var proxiedByApp: [String: [ProxiedRemote]] = [:]
        for r in unmasked.remotes {
            let ident = identityByPid[r.pid] ?? AppIdentity.resolve(processPath: r.path, pid: r.pid)
            proxiedByApp[ident.id, default: []].append(r)
            if table[ident.id] == nil { table[ident.id] = AppEntry(identity: ident) }
        }
        let resolveProxied = AppSettings.shared.resolveProxiedHosts

        var rxByApp: [String: Double] = [:], txByApp: [String: Double] = [:]
        var totalRx = 0.0, totalTx = 0.0
        for t in traffic {
            defer { previous[t.pid] = t }
            guard let p = previous[t.pid], t.bytesIn >= p.bytesIn, t.bytesOut >= p.bytesOut else { continue }
            let dIn = Double(t.bytesIn - p.bytesIn), dOut = Double(t.bytesOut - p.bytesOut)
            totalRx += dIn; totalTx += dOut
            let ident: AppIdentity
            if let i = identityByPid[t.pid] { ident = i } else {
                let path = ConnectionSampler.path(of: t.pid)
                guard !path.hasPrefix("pid ") else { continue }
                ident = AppIdentity.resolve(processPath: path, pid: t.pid)
                identityByPid[t.pid] = ident
                if table[ident.id] == nil { table[ident.id] = AppEntry(identity: ident) }
                noteProcess(t.pid, path: path, in: ident)
            }
            rxByApp[ident.id, default: 0] += dIn; txByApp[ident.id, default: 0] += dOut
            table[ident.id]!.totalIn += UInt64(dIn); table[ident.id]!.totalOut += UInt64(dOut)
            table[ident.id]!.pids.insert(t.pid)
            if let name = processNames[t.pid] {
                table[ident.id]!.processes[name]?.totalIn += UInt64(dIn); table[ident.id]!.processes[name]?.totalOut += UInt64(dOut)
            }
        }
        sessionIn += UInt64(totalRx); sessionOut += UInt64(totalTx)
        rateIn = totalRx / dt; rateOut = totalTx / dt
        history.append(TrafficPoint(date: now, rx: totalRx, tx: totalTx))
        if history.count > 2400 { history.removeFirst(history.count - 2400) }
        let minute = Date(timeIntervalSince1970: (now.timeIntervalSince1970 / 60).rounded(.down) * 60)
        var b = buckets[minute] ?? Bucket(minute: minute, rx: 0, tx: 0)
        b.rx += totalRx; b.tx += totalTx
        buckets[minute] = b

        var denyCount = 0, askCount = 0, listenCount = 0
        let wholeAppDenied = deniedAppPaths
        var portsNow = Set<Int>(), loopbackNow = Set<Int>(), liveSockets = Set<String>()
        for id in table.keys {
            var e = table[id]!
            let rx = rxByApp[id] ?? 0, tx = txByApp[id] ?? 0
            e.rates.append((rx, tx)); if e.rates.count > 14 { e.rates.removeFirst() }
            if rx + tx > 0 || perApp[id] != nil || proxiedByApp[id] != nil { e.lastActive = now }
            e.listening = perApp[id]?.listening ?? 0
            listenCount += e.listening
            if perApp[id] == nil { e.pids = e.pids.filter { pid in traffic.contains { $0.pid == pid } } }
            for name in e.processes.keys { e.processes[name]!.pids.formIntersection(alive) }
            e.otherUsers = !e.pids.isEmpty && e.pids.allSatisfy { ownerUID(of: $0) != getuid() }

            var remotes: [RemoteHost] = []
            var seen = Set<String>()
            var indexByKey: [String: Int] = [:]
            var deniedKeys = Set<String>()
            let sig = e.remotes.isEmpty && perApp[id] == nil && proxiedByApp[id] == nil ? (nil as String?, nil as String?) : signing(for: e.identity)
            /// The verdict for one remote, counted and (for `.ask`) reported as an alert.
            /// `host` is the name shown (the address itself when there is none); a name that is an IP literal is no name.
            /// `executable` is the process that holds the socket, for rules about one of the app's processes.
            /// A connection a peer started is judged too (an app's ✗ cuts it, as the helper does), but never asks.
            func judge(host: String, address: String, port: Int, proto: Connection.Proto, executable: String, route: RouteTag? = nil, incoming: Bool = false) -> Verdict? {
                let conn = Connection(process: ProcessIdentity(signingID: sig.0, teamID: sig.1, path: e.identity.ruleKey), executable: executable,
                                      host: host == address || isIPLiteral(host) ? nil : host, address: address, port: port, proto: proto)
                // The process list's ✗/✓ decide first, narrowest first (`RuleEngine.decide`). Matches what is
                // enforced: an app the helper blocks as a whole (`deniedAppPaths`) is denied for every server.
                let decision = rules.engine.decide(conn)
                let verdict: Verdict = decision.rule?.effectiveListLevel == nil && wholeAppDenied.contains(e.identity.ruleKey) ? .deny : decision.verdict
                if incoming && verdict == .ask { return nil }
                if decision.rule == nil, verdict != .ask, warmedUp, !incoming { noteSilentConnection(app: e.identity.name, host: host, allowed: verdict == .allow) }
                switch verdict {
                case .deny: denyCount += 1
                case .ask:
                    askCount += 1
                    if warmedUp {
                        alerts.report(ConnectionAlert(appID: e.identity.ruleKey, appName: e.identity.name, host: host, address: address, port: port, proto: proto.rawValue.uppercased(),
                                                      network: address.isEmpty || isLocalAddress(address) ? nil : geo.network(address)?.label, route: route?.label,
                                                      executable: executable))
                    }
                case .allow: break
                }
                return verdict
            }
            for c in perApp[id]?.conns ?? [] where !unmasked.masked.contains(ProxyUnmasking.maskKey(pid: c.pid, localPort: c.localPort, remotePort: c.remotePort)) {
                // A peer's connections to one port of this Mac are one row (each comes from a port of its own).
                let key = c.incoming ? "in|\(c.remoteAddress):\(c.localPort)/\(c.proto.rawValue)|\(c.processName)"
                                     : "\(c.remoteAddress):\(c.remotePort)/\(c.proto.rawValue)|\(c.processName)"
                let bytes = bytesByFlow[FlowCounter.key(pid: c.pid, proto: c.proto, localPort: c.localPort, remotePort: c.remotePort)]
                let socket = StreamDetector.key(pid: c.pid, proto: c.proto, localPort: c.localPort, remoteAddress: c.remoteAddress, remotePort: c.remotePort)
                liveSockets.insert(socket)
                let stream = !c.incoming && bytes != nil && streams.update(socket, bytesIn: bytes?.0 ?? 0, bytesOut: bytes?.1 ?? 0, now: now)
                // Several sockets to the same server, port and protocol are one row; their bytes add up.
                if let i = indexByKey[key] {
                    remotes[i].bytesIn += bytes?.0 ?? 0; remotes[i].bytesOut += bytes?.1 ?? 0
                    if stream { remotes[i].stream = true }
                    // Each of them has its own local port, and all are cut.
                    if deniedKeys.contains(key), c.localPort != 0 { portsNow.insert(c.localPort) }
                    continue
                }
                guard seen.insert(key).inserted else { continue }
                let (host, named) = names.lookup(c.remoteAddress)
                let geoPoint = isLocalAddress(c.remoteAddress) ? nil : geo.lookup(c.remoteAddress)
                // A peer that connected to a local proxy does not go through it: only an outgoing connection is tagged.
                let route = routes.route(localAddress: c.localAddress, remoteAddress: c.remoteAddress, remotePort: c.remotePort, processPath: c.processPath)
                    ?? (c.incoming ? nil : RouteMarker.localProxy(remoteAddress: c.remoteAddress, remotePort: c.remotePort, pid: c.pid, listener: listeners[c.remotePort]))
                remotes.append(RemoteHost(address: c.remoteAddress, host: host, port: c.incoming ? c.localPort : c.remotePort, proto: c.proto.rawValue.uppercased(), geo: geoPoint,
                                          pid: c.pid, process: c.processName,
                                          network: isLocalAddress(c.remoteAddress) ? nil : geo.network(c.remoteAddress)?.label,
                                          route: route, bytesIn: bytes?.0 ?? 0, bytesOut: bytes?.1 ?? 0, incoming: c.incoming, stream: stream))
                indexByKey[key] = remotes.count - 1

                guard !isLocalAddress(c.remoteAddress) else { continue }
                // A connection whose name is still being looked up is judged on a later pass (at most
                // `HostNames.grace` later), so a rule for its domain matches and an alert names it.
                guard named else { continue }
                // Judged by the socket's own ports, as the helper judges it.
                let verdict = judge(host: host, address: c.remoteAddress, port: c.remotePort, proto: c.proto == .udp ? .udp : .tcp,
                                    executable: c.processPath, route: remotes.last?.route, incoming: c.incoming)
                remotes[remotes.count - 1].verdict = verdict
                if verdict == .deny { deniedKeys.insert(key); if c.localPort != 0 { portsNow.insert(c.localPort) } }
            }
            for r in proxiedByApp[id] ?? [] {
                // A rule that denies the real destination cuts the client's loopback connection to the proxy.
                let address = proxyResolver.address(for: r.host, enabled: resolveProxied)
                let process = (r.path as NSString).lastPathComponent
                let fresh = seen.insert("proxy|\(r.host):\(r.port)|\(r.hop.listener)|\(process)").inserted
                if fresh {
                    var hop = r.hop
                    // A forwarding proxy's one outside connection is the destination itself.
                    if hop.server != nil, hop.server == address { hop.server = nil }
                    hop.serverGeo = hop.server.flatMap { isLocalAddress($0) ? nil : geo.lookup($0) }
                    let point = address.flatMap { isLocalAddress($0) ? nil : geo.lookup($0) }
                    let bytes = bytesByFlow[FlowCounter.key(pid: r.pid, proto: .tcp, localPort: r.clientPort, remotePort: r.proxyPort)]
                    remotes.append(RemoteHost(address: address ?? "", host: r.host, port: r.port, proto: "TCP", geo: point, via: hop, pid: r.pid, process: process,
                                              network: address.flatMap { isLocalAddress($0) ? nil : geo.network($0)?.label },
                                              bytesIn: bytes?.0 ?? 0, bytesOut: bytes?.1 ?? 0))
                }
                let verdict = judge(host: r.host, address: address ?? "", port: r.port, proto: .tcp, executable: r.path) ?? .ask
                if fresh { remotes[remotes.count - 1].verdict = verdict }
                if verdict == .deny, r.live { loopbackNow.insert(r.clientPort) }
            }
            e.remotes = remotes
            table[id] = e
        }
        streams.keep(only: liveSockets)
        deniedCount = denyCount; unconfirmedCount = askCount; incomingCount = listenCount
        deniedPorts = portsNow
        deniedLoopbackPorts = loopbackNow
        processNames = processNames.filter { alive.contains($0.key) }
        launchers = launchers.filter { alive.contains($0.key) }
        apps = Array(table.values)
    }

    private var uidCache: [Int32: uid_t] = [:]
    private var processNames: [Int32: String] = [:]

    /// Records which executable a pid runs, under its app, and for a command-line tool the app that started it.
    private func noteProcess(_ pid: Int32, path: String, in ident: AppIdentity) {
        let name = (path as NSString).lastPathComponent
        processNames[pid] = name
        guard table[ident.id] != nil else { return }
        if table[ident.id]!.processes[name] == nil { table[ident.id]!.processes[name] = ProcessStats(name: name, path: path) }
        table[ident.id]!.processes[name]!.pids.insert(pid)
        guard !ident.isSystem, ident.bundlePath == nil, table[ident.id]!.launchedBy == nil else { return }
        if launchers[pid] == nil {
            launchers[pid] = .some(ProcessGrouping.launchingApp(of: pid).map { "\(AppIdentity.resolve(processPath: $0.path).name) (pid \($0.pid))" })
        }
        table[ident.id]!.launchedBy = launchers[pid] ?? nil
    }

    private func ownerUID(of pid: Int32) -> uid_t {
        if let u = uidCache[pid] { return u }
        var info = proc_bsdinfo()
        let n = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, Int32(MemoryLayout<proc_bsdinfo>.size))
        let uid = n == Int32(MemoryLayout<proc_bsdinfo>.size) ? info.pbi_uid : getuid()
        uidCache[pid] = uid
        return uid
    }

    private var notifiedSilent = Set<String>()

    /// "Silent Mode Connections": tell the user the first time a connection was allowed or denied without asking.
    private func noteSilentConnection(app: String, host: String, allowed: Bool) {
        guard AppSettings.shared.notifySilentConnections, notifiedSilent.insert("\(app)|\(registrableDomain(host))").inserted else { return }
        Notifier.post(title: allowed ? "Silent Mode: connection allowed" : "Silent Mode: connection denied", body: "\(app) → \(host)")
    }

    // MARK: blocking

    /// Allow/Deny from the process list. Deny is enforced by the root helper from the next pass (see `deniedAppPaths`).
    func setPolicy(_ p: Policy?, for appID: String) {
        rules.setPolicy(p, for: table[appID]?.identity.ruleKey ?? appID)
        alerts.revalidate()
        refreshEnforcement()
        requestPass()
    }

    /// ✗/✓ for one process of an app (`executable`: its path). Enforced from the next pass, by the ports of its sockets.
    func setProcessPolicy(_ p: Policy?, app appID: String, executable: String) {
        rules.setProcessPolicy(p, app: table[appID]?.identity.ruleKey ?? appID, executable: executable)
        alerts.revalidate()
        refreshEnforcement()
        requestPass()
    }

    /// ✗/✓ for one connection of one process. Enforced from the next pass, by the ports of the sockets it matches.
    func setConnectionPolicy(_ p: Policy?, app appID: String, executable: String, _ endpoint: RulesModel.Endpoint) {
        rules.setConnectionPolicy(p, app: table[appID]?.identity.ruleKey ?? appID, executable: executable, endpoint)
        alerts.revalidate()
        refreshEnforcement()
        requestPass()
    }

    /// ✗/✓ for any row of the process list: an app, one of its processes, or one connection.
    func setPolicy(_ p: Policy?, for t: RulesModel.Target) {
        switch (t.executable, t.endpoint) {
        case (let exe?, let e?): setConnectionPolicy(p, app: t.app, executable: exe, e)
        case (let exe?, nil): setProcessPolicy(p, app: t.app, executable: exe)
        case (nil, _): setPolicy(p, for: t.app)
        }
    }

    /// Hands the helper what to block. Only ports of denied sockets are ever blocked, never server addresses.
    func refreshEnforcement() {
        enforcer.syncApps(deniedAppPaths)
        enforcer.syncPorts(deniedPorts, loopback: deniedLoopbackPorts)
        enforcer.syncRules(daemonRules)
        enforcer.refreshStatus()
    }

    /// What the helper is doing for one app: its processes and blocked ports, or nil if the helper sees none.
    func enforcement(for appID: String) -> EnforcerStatus.App? {
        let key = table[appID]?.identity.ruleKey ?? appID
        return enforcer.status?.deniedApps[key] ?? enforcer.status?.ruleDenied?[key]
    }

    /// Names of the servers of apps a deny rule names, as Rat judged them, kept after their connection closed (the
    /// next connection to the same server is judged by its name at once), newest last, at most `daemonNamesLimit`.
    private var daemonNames: [String: String] = [:]
    private var daemonNameOrder: [String] = []
    static let daemonNamesLimit = 2048

    /// What the daemon needs to judge sockets by the rules itself (`DaemonRules`): the active rules, and for the apps
    /// a deny rule names (or one of whose processes it names), the names Rat judged their servers by and their code
    /// signatures. Empty while no deny rule names a process, so the file changes only when it matters.
    var daemonRules: DaemonRules {
        let active = rules.engine.activeRules
        let denied = active.compactMap { $0.verdict == .deny ? $0.processPath : nil }
        guard !denied.isEmpty else { daemonNames.removeAll(); daemonNameOrder.removeAll(); return DaemonRules() }
        func inside(_ p: String, _ prefix: String) -> Bool { ProgramPath.inside(p, prefix) }
        var signatures: [String: DaemonRules.Signature] = [:]
        for e in table.values {
            let key = e.identity.ruleKey
            guard denied.contains(where: { p in inside(key, p) || inside(p, key) || e.processes.values.contains { inside($0.path, p) } }) else { continue }
            if let s = signingCache[e.identity.id] { signatures[key] = DaemonRules.Signature(signingID: s.identifier, teamID: s.team) }
            for r in e.remotes where r.verdict != nil && r.via == nil && !r.address.isEmpty {
                let name = r.host == r.address || isIPLiteral(r.host) ? "" : r.host
                if daemonNames.updateValue(name, forKey: r.address) == nil { daemonNameOrder.append(r.address) }
            }
        }
        if daemonNameOrder.count > Self.daemonNamesLimit {
            for a in daemonNameOrder.prefix(daemonNameOrder.count - Self.daemonNamesLimit) { daemonNames[a] = nil }
            daemonNameOrder.removeFirst(daemonNameOrder.count - Self.daemonNamesLimit)
        }
        return DaemonRules(rules: active, names: daemonNames, signatures: signatures, localRanges: AppSettings.shared.additionalLocalRanges)
    }

    /// Apps denied outright. The root daemon blocks every socket of their processes (helpers included), by local
    /// port, so it does not matter which server they try next. A Deny from the process list wins over the app's
    /// narrower allow rules; under Silent Deny an app with any allow rule is not blocked as a whole.
    var deniedAppPaths: Set<String> {
        var candidates = Set(table.values.map(\.identity.ruleKey))
        for r in rules.ruleSet.rules { if let p = r.processPath { candidates.insert(p) } }
        let active = rules.ruleSet.activeProfileID
        var out = Set<String>()
        for key in candidates where key.hasPrefix("/") && key != Bundle.main.bundlePath {
            // The red X in the process list denies the whole app, whatever narrower allow rules it has
            // (alerts in 1.0.0 created many: one domain, one address). Otherwise the list shows Deny and nothing
            // is blocked.
            // A ✓ on one of its processes or connections is an exception: then only the sockets the rules deny are cut.
            if rules.policy(for: key) == .deny { if !rules.hasNarrowerAllow(app: key) { out.insert(key) }; continue }
            let mine = rules.rules(for: key).filter { $0.enabled && ($0.profileID == nil || $0.profileID == active) }
            if mine.contains(where: { $0.verdict == .allow }) { continue }
            let probe = Connection(process: ProcessIdentity(path: key), address: "203.0.113.9", port: 443, proto: .tcp)
            if let m = rules.engine.matchingRule(probe) {
                let wholeApp = m.remoteDomain == nil && m.remoteHost == nil && m.remoteAddress == nil && m.ports == nil && m.proto == nil
                if m.verdict == .deny, wholeApp { out.insert(key) }
            } else if rules.engine.defaultVerdict == .deny {
                out.insert(key)
            }
        }
        return out
    }

    // MARK: derived data

    func domains(_ remotes: [RemoteHost]? = nil) -> [(name: String, count: Int)] {
        Self.tally(remotes ?? apps.flatMap(\.remotes)) { registrableDomain($0.host) }
    }

    /// Networks (ASN organizations) by number of connections, for the Summary.
    func networks(_ remotes: [RemoteHost]? = nil) -> [(name: String, count: Int)] {
        Self.tally(remotes ?? apps.flatMap(\.remotes)) { $0.network }
    }

    func countries(_ remotes: [RemoteHost]? = nil) -> [(name: String, count: Int)] {
        Self.tally(remotes ?? apps.flatMap(\.remotes)) { $0.geo?.country }
    }

    /// Connections by key, most first (ties by name).
    private static func tally(_ remotes: [RemoteHost], _ key: (RemoteHost) -> String?) -> [(name: String, count: Int)] {
        var d: [String: Int] = [:]
        for r in remotes { if let k = key(r) { d[k, default: 0] += 1 } }
        return d.map { ($0.key, $0.value) }.sorted { $0.1 > $1.1 || ($0.1 == $1.1 && $0.0 < $1.0) }
    }

    /// The inspector's Summary: every app, or with a search or chip on, the listed apps and their matching
    /// connections (the same set the map draws). Unfiltered, the totals are the session's.
    func summary(_ filter: MonitorFilter, settings: AppSettings? = nil) -> MonitorSummary {
        guard filter.isActive else {
            // Hide Local is a standing preference, not a filter: the totals stay the session's.
            let shown = filter.hideLocal ? apps.filter { !$0.onlyLocal } : apps
            let remotes = shown.flatMap(\.remotes).filter { !(filter.hideLocal && $0.isLocal) }
            return MonitorSummary(filtered: false, apps: shown, remotes: remotes, bytesIn: sessionIn, bytesOut: sessionOut,
                                  denied: deniedCount, unconfirmed: unconfirmedCount, incoming: incomingCount)
        }
        let listed = filter.apps(self, settings: settings ?? .shared)
        let remotes = listed.flatMap { a in a.remotes.filter { filter.matches($0, of: a) } }
        return MonitorSummary(filtered: true, apps: listed, remotes: remotes,
                              bytesIn: listed.reduce(0) { $0 + $1.totalIn }, bytesOut: listed.reduce(0) { $0 + $1.totalOut },
                              denied: remotes.filter { $0.verdict == .deny }.count, unconfirmed: remotes.filter { $0.verdict == .ask }.count,
                              incoming: listed.reduce(0) { $0 + $1.listening })
    }

    /// Bars for the traffic chart. The window shrinks to the data that exists (never a lone sliver on the right edge)
    /// and the bars are sized so that they tile it completely.
    func chartLayout(_ range: TimeRange, now: Date = Date()) -> ChartLayout {
        let windowStart = now.addingTimeInterval(-range.seconds)
        // (time, rx, tx) samples: live samples up to an hour, minute buckets beyond.
        let samples: [(Date, Double, Double)] = range.seconds <= 3600
            ? history.filter { $0.date >= windowStart }.map { ($0.date, $0.rx, $0.tx) }
            : buckets.values.filter { $0.minute >= windowStart }.map { ($0.minute, $0.rx, $0.tx) }
        let minSpan = min(range.seconds, 60.0)
        let first = samples.map(\.0).min() ?? now.addingTimeInterval(-minSpan)
        let start = min(max(windowStart, first), now.addingTimeInterval(-minSpan))
        let span = now.timeIntervalSince(start)
        let floorSize: TimeInterval = range.seconds <= 3600 ? 1.5 : 60
        let size = max(span / 60, floorSize)
        let count = max(Int((span / size).rounded(.up)), 1)
        var rx = [Double](repeating: 0, count: count), tx = [Double](repeating: 0, count: count)
        for (t, r, x) in samples {
            let i = min(max(Int(t.timeIntervalSince(start) / size), 0), count - 1)
            rx[i] += r; tx[i] += x
        }
        let starts = (0..<count).map { start.addingTimeInterval(Double($0) * size) }
        let ends = (0..<count).map { start.addingTimeInterval(Double($0 + 1) * size) }
        // Square-root scale so quiet traffic stays visible next to a burst.
        for i in 0..<count { rx[i] = rx[i].squareRoot(); tx[i] = tx[i].squareRoot() }
        let bars = zip(zip(starts, ends), zip(rx, tx)).map { ChartBar(start: $0.0.0, end: $0.0.1, rx: $0.1.0, tx: $0.1.1) }
        let peak = max((rx + tx).max() ?? 0, 1) * 1.1
        let format: Date.FormatStyle = range == .week ? .dateTime.weekday(.abbreviated).day()
            : range == .fiveMinutes ? .dateTime.hour().minute().second() : .dateTime.hour().minute()
        return ChartLayout(bars: bars, start: start, end: start.addingTimeInterval(Double(count) * size), peak: peak, labelFormat: format)
    }

    #if DEBUG
    /// Fixed data for visual checks and snapshot tests: no sampling, no alerts, no real addresses.
    func installDemoData() {
        demo = true
        myLocation = GeoPoint(coordinate: .init(latitude: 52.52, longitude: 13.405), city: "Berlin", country: "Germany", countryCode: "DE")
        let codes = ["United Kingdom": "GB", "Netherlands": "NL", "Germany": "DE", "France": "FR", "Sweden": "SE", "Spain": "ES"]
        // (app, process, pid, host, address, proto, port, city, country, lat, lon): each app's main process and helpers,
        // the macOS row's services, and a command-line tool. Documentation addresses only (RFC 5737).
        let conns: [(String, String, Int32, String, String, String, Int, String, String, Double, Double)] = [
            ("Google Chrome", "Google Chrome", 401, "demo0.example.com", "203.0.113.1", "TCP", 443, "London", "United Kingdom", 51.507, -0.128),
            ("Google Chrome", "Google Chrome", 401, "demo1.example.com", "203.0.113.2", "TCP", 443, "Amsterdam", "Netherlands", 52.37, 4.89),
            ("Google Chrome", "Google Chrome Helper", 412, "cdn.example.net", "198.51.100.5", "UDP", 443, "Frankfurt", "Germany", 50.11, 8.68),
            ("Google Chrome", "Google Chrome Helper", 413, "video.example.net", "198.51.100.6", "TCP", 443, "Paris", "France", 48.857, 2.352),
            ("Telegram", "Telegram", 520, "demo2.example.com", "203.0.113.3", "TCP", 443, "Frankfurt", "Germany", 50.11, 8.68),
            ("Telegram", "Telegram Helper", 521, "demo3.example.com", "203.0.113.4", "TCP", 5222, "Paris", "France", 48.857, 2.352),
            ("Steam", "Steam", 630, "demo4.example.com", "203.0.113.5", "TCP", 27036, "Stockholm", "Sweden", 59.33, 18.07),
            ("Steam", "Steam Helper", 641, "demo5.example.com", "203.0.113.6", "UDP", 27015, "Madrid", "Spain", 40.42, -3.70),
            ("macOS", "mDNSResponder", 90, "dns.example", "192.0.2.53", "UDP", 53, "Amsterdam", "Netherlands", 52.37, 4.89),
            ("macOS", "apsd", 95, "push.example", "192.0.2.80", "TCP", 5223, "Stockholm", "Sweden", 59.33, 18.07),
            ("git-remote-https", "git-remote-https", 760, "git.example.org", "198.51.100.20", "TCP", 443, "Madrid", "Spain", 40.42, -3.70),
        ]
        func demoPath(_ app: String, _ process: String) -> String {
            switch app {
            case "macOS": return "/usr/sbin/\(process)"
            case "git-remote-https": return "/opt/homebrew/opt/git/libexec/git-core/git-remote-https"
            case "Steam": return "/Applications/Demo/Steam.app/Contents/MacOS/\(process)"
            default: return "/Applications/Demo/\(app).app/Contents/\(process == app ? "MacOS" : "Frameworks/\(process).app/Contents/MacOS")/\(process)"
            }
        }
        for (i, c) in conns.enumerated() {
            let path = demoPath(c.0, c.1)
            let ident = c.0 == "macOS" ? AppIdentity(id: "macOS", name: "macOS", bundlePath: nil, isSystem: true) : AppIdentity.resolve(processPath: path)
            var e = table[ident.id] ?? AppEntry(identity: ident)
            e.lastActive = Date(); e.totalIn += UInt64(1_000_000 * (i + 1)); e.totalOut += UInt64(100_000 * (i + 1))
            if e.rates.isEmpty {
                e.rates = (0..<14).map { k in (rx: Double((k * (i + 3)) % 7), tx: Double((k * (i + 2)) % 5)) }
            }
            e.pids.insert(c.2)
            var stats = e.processes[c.1] ?? ProcessStats(name: c.1, path: path)
            stats.pids.insert(c.2); stats.totalIn += UInt64(400_000 * (i + 1)); stats.totalOut += UInt64(40_000 * (i + 1))
            e.processes[c.1] = stats
            e.remotes.append(RemoteHost(address: c.4, host: c.3, port: c.6, proto: c.5,
                                        geo: GeoPoint(coordinate: .init(latitude: c.9, longitude: c.10), city: c.7, country: c.8, countryCode: codes[c.8] ?? ""),
                                        pid: c.2, process: c.1, network: "AS64500 Example Networks",
                                        bytesIn: UInt64(250_000 * (i + 1)), bytesOut: UInt64(25_000 * (i + 1))))
            if c.0 == "git-remote-https" { e.launchedBy = "Warp (pid 700)" }
            if c.3 == "demo3.example.com" { e.remotes[e.remotes.count - 1].route = .vpn(name: "Windscribe", interface: "utun3") }
            // A peer connected to Steam's Remote Play port; Telegram's main connection is a long download.
            if c.3 == "demo4.example.com" { e.remotes[e.remotes.count - 1].incoming = true }
            if c.3 == "demo2.example.com" { e.remotes[e.remotes.count - 1].stream = true }
            table[ident.id] = e
        }
        // Firefox through local proxies: one destination unmasked behind `ssh -D 1080`, one connection to Tor that
        // was not unmasked.
        let firefox = AppIdentity.resolve(processPath: "/Applications/Demo/Firefox.app/Contents/MacOS/Firefox")
        var fx = AppEntry(identity: firefox)
        fx.lastActive = Date(); fx.totalIn = 3_000_000; fx.totalOut = 300_000; fx.pids = [880]
        fx.rates = (0..<14).map { k in (rx: Double(k % 6), tx: Double(k % 3)) }
        fx.processes["Firefox"] = ProcessStats(name: "Firefox", path: "/Applications/Demo/Firefox.app/Contents/MacOS/Firefox", pids: [880], totalIn: 3_000_000, totalOut: 300_000)
        let stockholm = GeoPoint(coordinate: .init(latitude: 59.33, longitude: 18.07), city: "Stockholm", country: "Sweden", countryCode: "SE")
        fx.remotes = [
            RemoteHost(address: "198.51.100.30", host: "news.example.org", port: 443, proto: "TCP",
                       geo: GeoPoint(coordinate: .init(latitude: 40.42, longitude: -3.70), city: "Madrid", country: "Spain", countryCode: "ES"),
                       via: ProxyHop(kind: "SOCKS5", process: "ssh", listener: "127.0.0.1:1080", server: "192.0.2.10", serverGeo: stockholm),
                       pid: 880, process: "Firefox", network: "AS64500 Example Networks", bytesIn: 900_000, bytesOut: 60_000),
            RemoteHost(address: "127.0.0.1", host: "127.0.0.1", port: 9050, proto: "TCP", pid: 880, process: "Firefox",
                       route: .localProxy(program: "Tor", listener: "127.0.0.1:9050"), bytesIn: 120_000, bytesOut: 9_000),
        ]
        table[firefox.id] = fx
        // Traffic that stays near this Mac, for Hide Local: Bonjour, and a service that talks only to the LAN.
        if var mac = table["macOS"] {
            mac.remotes.append(RemoteHost(address: "224.0.0.251", host: "224.0.0.251", port: 5353, proto: "UDP", pid: 90, process: "mDNSResponder"))
            mac.remotes.append(RemoteHost(address: "192.168.1.20", host: "192.168.1.20", port: 49152, proto: "TCP", pid: 96, process: "rapportd",
                                          bytesIn: 40_000, bytesOut: 30_000))
            mac.processes["rapportd"] = ProcessStats(name: "rapportd", path: "/usr/libexec/rapportd", pids: [96], totalIn: 40_000, totalOut: 30_000)
            mac.pids.insert(96)
            table["macOS"] = mac
        }
        let chrome = "/Applications/Demo/Google Chrome.app", telegram = "/Applications/Demo/Telegram.app", steam = "/Applications/Demo/Steam.app"
        var pending = Rule(verdict: .deny, processPath: telegram, remoteDomain: "tracker.example", createdAt: Date(timeIntervalSinceNow: -60), note: "From a connection alert")
        pending.approved = false
        rules.ruleSet.rules = [
            pending,
            Rule(verdict: .allow, processPath: chrome, createdAt: Date(timeIntervalSinceNow: -120), note: "From the process list"),
            Rule(verdict: .allow, processPath: steam, ports: 27015...27030, proto: .udp, createdAt: Date(timeIntervalSinceNow: -180)),
            Rule(verdict: .deny, remoteDomain: "ads.example", createdAt: Date(timeIntervalSinceNow: -240)),
        ]
        sessionIn = 12_400_000; sessionOut = 1_300_000
        unconfirmedCount = 6
        var points: [TrafficPoint] = []
        for k in 0..<60 {
            let date = Date().addingTimeInterval(Double(k - 60) * 5)
            let rx = Double((k * 37) % 90) * 1000
            let tx = Double((k * 53) % 40) * 1000
            points.append(TrafficPoint(date: date, rx: rx, tx: tx))
        }
        history = points
        apps = Array(table.values)
    }
    #endif
}

/// The service usually on a port, for display: "HTTPS" for TCP 443, "QUIC" for UDP 443. A hint only: any program
/// can use any port.
func usualService(proto: String, port: Int) -> String? {
    PortNames.name(port: port, proto: proto.uppercased() == "UDP" ? .udp : .tcp)
}

/// " · HTTPS" after a port, or nothing.
func serviceSuffix(proto: String, port: Int) -> String {
    usualService(proto: proto, port: port).map { " · \($0)" } ?? ""
}

func formatBytes(_ n: UInt64) -> String {
    let f = ByteCountFormatter()
    f.countStyle = .file
    f.allowsNonnumericFormatting = false   // "0 bytes" instead of "Zero KB"
    return f.string(fromByteCount: Int64(n))
}
