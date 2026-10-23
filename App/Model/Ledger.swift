import SwiftUI
import CoreLocation
import RatMonitor
import RatFilterCore
import RatEnforce
import os

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

struct RemoteHost: Identifiable, Hashable {
    var id: String { address }
    let address: String
    var host: String
    var port: Int
    var proto: String
    var geo: GeoPoint?
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
    private(set) lazy var alerts: AlertCenter = {
        let center = AlertCenter(rules: rules) { [unowned self] alert, verdict in
            refreshEnforcement()
        }
        center.isStillPending = { [unowned self] a in
            let c = Connection(process: ProcessIdentity(path: a.appID), host: a.host == a.address ? nil : a.host, address: a.address, port: a.port,
                               proto: a.proto == "UDP" ? .udp : .tcp)
            return rules.engine.evaluate(c) == .ask
        }
        return center
    }()
    var onTick: (() -> Void)?

    private let names = HostNames()
    private let store: StateStore
    private var previous: [Int32: TrafficCounter] = [:]
    private var table: [String: AppEntry] = [:]
    private var buckets: [Date: Bucket] = [:]
    private var deniedPorts = Set<Int>()
    private var signingCache: [String: (identifier: String?, team: String?)] = [:]
    private var running = false
    private var demo = false
    private var lastSave = Date()
    private var lastTick = Date()
    private var startedAt = Date()

    init(directory: URL? = nil, helperInstalled: Bool? = nil) {
        #if DEBUG
        // Demo mode never reads or writes the real data folder.
        let demoDir = ProcessInfo.processInfo.environment["RAT_DEMO_MAP"] != nil ? FileManager.default.temporaryDirectory.appendingPathComponent("rat-demo-\(UUID())") : nil
        store = StateStore.standard(base: directory ?? demoDir)
        #else
        store = StateStore.standard(base: directory)
        #endif
        rules = RulesModel(directory: store.directory)
        enforcer = Enforcer(supportDirectory: store.directory, helperInstalled: helperInstalled,
                            statusPath: helperInstalled == nil ? nil : store.directory.appendingPathComponent("enforcer-status.json").path)
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
        #if DEBUG
        if ProcessInfo.processInfo.environment["RAT_DEMO_MAP"] != nil { installDemoData() }
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
        save()
    }

    private func loop() async {
        while running && !demo {
            let useSnapshot = enforcer.systemSnapshotText()
            let (conns, traffic) = await Task.detached(priority: .utility) { () -> ([ObservedConnection], [TrafficCounter]) in
                var c = ConnectionSampler.sample()
                if let text = useSnapshot {
                    // Root helper snapshot: adds processes this app cannot inspect (other users, system daemons).
                    var seen = Set(c.map { "\($0.pid)|\($0.proto.rawValue)|\($0.localPort)|\($0.remoteAddress)|\($0.remotePort)" })
                    for x in SystemSnapshot.parse(text) where seen.insert("\(x.pid)|\(x.proto.rawValue)|\(x.localPort)|\(x.remoteAddress)|\(x.remotePort)").inserted { c.append(x) }
                }
                return (c, TrafficSampler.sample())
            }.value
            systemWide = useSnapshot != nil
            await ingest(conns, traffic)
            rules.refreshNetwork()
            refreshEnforcement()
            alerts.revalidate()
            onTick?()
            if Date().timeIntervalSince(lastSave) > 30 { save() }
            try? await Task.sleep(for: .seconds(1.5))
        }
    }

    // MARK: sampling

    private func signing(for identity: AppIdentity) -> (identifier: String?, team: String?) {
        if let c = signingCache[identity.id] { return c }
        let s = identity.signing()
        signingCache[identity.id] = s
        return s
    }

    private func ingest(_ conns: [ObservedConnection], _ traffic: [TrafficCounter]) async {
        let now = Date()
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
        }

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
                if table[ident.id] == nil { table[ident.id] = AppEntry(identity: ident) }
            }
            rxByApp[ident.id, default: 0] += dIn; txByApp[ident.id, default: 0] += dOut
            table[ident.id]!.totalIn += UInt64(dIn); table[ident.id]!.totalOut += UInt64(dOut)
            table[ident.id]!.pids.insert(t.pid)
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
        var portsNow = Set<Int>()
        for id in table.keys {
            var e = table[id]!
            let rx = rxByApp[id] ?? 0, tx = txByApp[id] ?? 0
            e.rates.append((rx, tx)); if e.rates.count > 14 { e.rates.removeFirst() }
            if rx + tx > 0 || perApp[id] != nil { e.lastActive = now }
            e.listening = perApp[id]?.listening ?? 0
            listenCount += e.listening
            if perApp[id] == nil { e.pids = e.pids.filter { pid in traffic.contains { $0.pid == pid } } }
            e.otherUsers = !e.pids.isEmpty && e.pids.allSatisfy { ownerUID(of: $0) != getuid() }

            var remotes: [RemoteHost] = []
            var seen = Set<String>()
            let sig = e.remotes.isEmpty && perApp[id] == nil ? (nil as String?, nil as String?) : signing(for: e.identity)
            for c in perApp[id]?.conns ?? [] where seen.insert("\(c.remoteAddress):\(c.remotePort)").inserted {
                let host = await names.name(for: c.remoteAddress)
                let geoPoint = isLocalAddress(c.remoteAddress) ? nil : geo.lookup(c.remoteAddress)
                remotes.append(RemoteHost(address: c.remoteAddress, host: host, port: c.remotePort, proto: c.proto.rawValue.uppercased(), geo: geoPoint))

                guard !isLocalAddress(c.remoteAddress) else { continue }
                                let conn = Connection(process: ProcessIdentity(signingID: sig.0, teamID: sig.1, path: e.identity.ruleKey), host: host == c.remoteAddress ? nil : host,
                                      address: c.remoteAddress, port: c.remotePort, proto: c.proto == .udp ? .udp : .tcp)
                let matched = rules.engine.matchingRule(conn)
                // Matches what is enforced: an app denied from the process list is denied for every server.
                let verdict = wholeAppDenied.contains(e.identity.ruleKey) ? .deny : (matched?.verdict ?? rules.engine.defaultVerdict)
                if matched == nil, verdict != .ask, warmedUp { noteSilentConnection(app: e.identity.name, host: host, allowed: verdict == .allow) }
                switch verdict {
                case .deny:
                    denyCount += 1
                    if c.localPort != 0 { portsNow.insert(c.localPort) }
                case .ask:
                    askCount += 1
                    if warmedUp {
                        alerts.report(ConnectionAlert(appID: e.identity.ruleKey, appName: e.identity.name, host: host, address: c.remoteAddress, port: c.remotePort, proto: remotes.last!.proto))
                    }
                case .allow: break
                }
            }
            e.remotes = remotes
            table[id] = e
        }
        deniedCount = denyCount; unconfirmedCount = askCount; incomingCount = listenCount
        deniedPorts = portsNow
        apps = Array(table.values)
    }

    private var uidCache: [Int32: uid_t] = [:]

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
    }

    /// Hands the helper what to block. Only ports of denied sockets are ever blocked, never server addresses.
    func refreshEnforcement() {
        enforcer.syncApps(deniedAppPaths)
        enforcer.syncPorts(deniedPorts)
        enforcer.refreshStatus()
    }

    /// What the helper is doing for one app: its processes and blocked ports, or nil if the helper sees none.
    func enforcement(for appID: String) -> EnforcerStatus.App? {
        enforcer.status?.deniedApps[table[appID]?.identity.ruleKey ?? appID]
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
            if rules.policy(for: key) == .deny { out.insert(key); continue }
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

    func domains() -> [(name: String, count: Int)] {
        var d: [String: Int] = [:]
        for a in apps { for r in a.remotes { d[registrableDomain(r.host), default: 0] += 1 } }
        return d.map { ($0.key, $0.value) }.sorted { $0.1 > $1.1 }
    }

    func countries() -> [(name: String, count: Int)] {
        var d: [String: Int] = [:]
        for a in apps { for r in a.remotes { if let c = r.geo?.country { d[c, default: 0] += 1 } } }
        return d.map { ($0.key, $0.value) }.sorted { $0.1 > $1.1 }
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
        myLocation = GeoPoint(coordinate: .init(latitude: 52.52, longitude: 13.405), city: "Berlin", country: "Germany")
        let places: [(String, String, String, Double, Double)] = [
            ("Google Chrome", "London", "United Kingdom", 51.507, -0.128), ("Google Chrome", "Amsterdam", "Netherlands", 52.37, 4.89),
            ("Telegram", "Frankfurt", "Germany", 50.11, 8.68), ("Telegram", "Paris", "France", 48.857, 2.352),
            ("Steam", "Stockholm", "Sweden", 59.33, 18.07), ("Steam", "Madrid", "Spain", 40.42, -3.70),
        ]
        for (i, d) in places.enumerated() {
            let ident = AppIdentity.resolve(processPath: "/Applications/Demo/\(d.0).app/Contents/MacOS/x")
            var e = table[ident.id] ?? AppEntry(identity: ident)
            e.lastActive = Date(); e.totalIn = UInt64(1_000_000 * (i + 1)); e.totalOut = UInt64(100_000 * (i + 1))
            var rates: [(rx: Double, tx: Double)] = []
            for k in 0..<14 { rates.append((rx: Double((k * (i + 3)) % 7), tx: Double((k * (i + 2)) % 5))) }
            e.rates = rates
            e.remotes.append(RemoteHost(address: "203.0.113.\(i + 1)", host: "demo\(i).example.com", port: 443, proto: "TCP",
                                        geo: GeoPoint(coordinate: .init(latitude: d.3, longitude: d.4), city: d.1, country: d.2)))
            table[ident.id] = e
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

func formatBytes(_ n: UInt64) -> String {
    let f = ByteCountFormatter()
    f.countStyle = .file
    f.allowsNonnumericFormatting = false   // "0 bytes" instead of "Zero KB"
    return f.string(fromByteCount: Int64(n))
}
