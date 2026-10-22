import SwiftUI
import CoreLocation
import RatMonitor
import os

private let logger = Logger(subsystem: "com.imanmontajabi.Rat", category: "ledger")

enum Policy: String { case allow, deny }

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
    let identity: AppIdentity
    var id: String { identity.id }
    var pids: Set<Int32> = []
    var remotes: [RemoteHost] = []
    var listening = 0
    var rates: [(rx: Double, tx: Double)] = []
    var totalIn: UInt64 = 0
    var totalOut: UInt64 = 0
    var lastActive = Date.distantPast
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
    @Published var myLocation: GeoPoint?
    @Published var policies: [String: Policy] = [:]
    @Published var geoEnabled = UserDefaults.standard.bool(forKey: "geoLookupEnabled")

    let enforcer: Enforcer

    private let geo = GeoService()
    private let names = HostNames()
    private let store = StateStore.standard()
    private var previous: [Int32: TrafficCounter] = [:]
    private var table: [String: AppEntry] = [:]
    private var buckets: [Date: Bucket] = [:]
    /// Server addresses each denied app has talked to.
    private var blocked: [String: Set<String>] = [:]
    private var running = false
    private var demo = false
    private var lastSave = Date()

    init() {
        enforcer = Enforcer(supportDirectory: store.directory)
        if let raw = UserDefaults.standard.dictionary(forKey: "policies") as? [String: String] {
            policies = raw.compactMapValues(Policy.init(rawValue:))
        }
        let saved = store.load()
        for a in saved.apps {
            let ident = AppIdentity(id: a.id, name: a.name, bundlePath: a.bundlePath, isSystem: a.isSystem)
            var e = AppEntry(identity: ident)
            e.totalIn = a.totalIn; e.totalOut = a.totalOut; e.lastActive = a.lastActive
            table[a.id] = e
        }
        blocked = saved.blocked.mapValues(Set.init)
        for b in saved.buckets { buckets[b.minute] = b }
        apps = Array(table.values)
        #if DEBUG
        if ProcessInfo.processInfo.environment["RAT_DEMO_MAP"] != nil { installDemoData() }
        #endif
    }

    // MARK: lifecycle

    func start() {
        guard !running else { return }
        running = true
        logger.notice("ledger started")
        Task { await loop() }
    }

    func save() {
        let weekAgo = Date().addingTimeInterval(-TimeRange.week.seconds)
        let state = PersistedState(
            apps: table.values.map { PersistedApp(id: $0.id, name: $0.identity.name, bundlePath: $0.identity.bundlePath, isSystem: $0.identity.isSystem, totalIn: $0.totalIn, totalOut: $0.totalOut, lastActive: $0.lastActive) },
            blocked: blocked.mapValues { Array($0) },
            buckets: buckets.values.filter { $0.minute > weekAgo }.sorted { $0.minute < $1.minute })
        store.save(state)
        UserDefaults.standard.set(policies.mapValues(\.rawValue), forKey: "policies")
        lastSave = Date()
    }

    func setGeoEnabled(_ on: Bool) {
        geoEnabled = on
        UserDefaults.standard.set(on, forKey: "geoLookupEnabled")
        if on { Task { await resolveGeo() } }
    }

    private func loop() async {
        while running && !demo {
            let (conns, traffic) = await Task.detached(priority: .utility) { (ConnectionSampler.sample(), TrafficSampler.sample()) }.value
            await ingest(conns, traffic)
            if geoEnabled { await resolveGeo() }
            if Date().timeIntervalSince(lastSave) > 30 { save() }
            try? await Task.sleep(for: .seconds(1.5))
        }
    }

    // MARK: sampling

    private func ingest(_ conns: [ObservedConnection], _ traffic: [TrafficCounter]) async {
        let now = Date()
        var identityByPid: [Int32: AppIdentity] = [:]
        var perApp: [String: (conns: [ObservedConnection], listening: Int)] = [:]
        for c in conns {
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
                ident = AppIdentity.resolve(processPath: ConnectionSampler.path(of: t.pid), pid: t.pid)
                if table[ident.id] == nil { table[ident.id] = AppEntry(identity: ident) }
            }
            rxByApp[ident.id, default: 0] += dIn; txByApp[ident.id, default: 0] += dOut
            table[ident.id]!.totalIn += UInt64(dIn); table[ident.id]!.totalOut += UInt64(dOut)
            table[ident.id]!.pids.insert(t.pid)
        }
        sessionIn += UInt64(totalRx); sessionOut += UInt64(totalTx)
        history.append(TrafficPoint(date: now, rx: totalRx, tx: totalTx))
        if history.count > 2400 { history.removeFirst(history.count - 2400) }
        let minute = Date(timeIntervalSince1970: (now.timeIntervalSince1970 / 60).rounded(.down) * 60)
        var b = buckets[minute] ?? Bucket(minute: minute, rx: 0, tx: 0)
        b.rx += totalRx; b.tx += totalTx
        buckets[minute] = b

        for id in table.keys {
            var e = table[id]!
            let rx = rxByApp[id] ?? 0, tx = txByApp[id] ?? 0
            e.rates.append((rx, tx)); if e.rates.count > 14 { e.rates.removeFirst() }
            if rx + tx > 0 || perApp[id] != nil { e.lastActive = now }
            e.listening = perApp[id]?.listening ?? 0
            if perApp[id] == nil { e.pids = e.pids.filter { pid in traffic.contains { $0.pid == pid } } }
            var remotes: [RemoteHost] = []
            var seen = Set<String>()
            for c in perApp[id]?.conns ?? [] where seen.insert("\(c.remoteAddress):\(c.remotePort)").inserted {
                let host = await names.name(for: c.remoteAddress)
                let old = e.remotes.first { $0.address == c.remoteAddress }
                remotes.append(RemoteHost(address: c.remoteAddress, host: host, port: c.remotePort, proto: c.proto.rawValue.uppercased(), geo: old?.geo))
            }
            e.remotes = remotes
            table[id] = e
            if policies[id] == .deny {
                var set = blocked[id] ?? []
                for r in remotes where !isLocalAddress(r.address) && set.count < 2000 { set.insert(r.address) }
                blocked[id] = set
            }
        }
        apps = Array(table.values)
    }

    private func resolveGeo() async {
        guard !demo else { return }
        if myLocation == nil { myLocation = await geo.lookup("") }
        var changed = false
        for (id, var e) in table {
            for i in e.remotes.indices where e.remotes[i].geo == nil && !isLocalAddress(e.remotes[i].address) {
                if let p = await geo.lookup(e.remotes[i].address) { e.remotes[i].geo = p; changed = true }
            }
            table[id] = e
        }
        if changed { apps = Array(table.values) }
    }

    // MARK: policy and blocking

    func setPolicy(_ p: Policy?, for id: String) {
        policies[id] = p
        if p != .deny { blocked[id] = nil } else if let e = table[id] {
            blocked[id] = Set(e.remotes.map(\.address).filter { !isLocalAddress($0) })
        }
        save()
    }

    /// Every address that should currently be blocked.
    var wantedBlocklist: Set<String> {
        var all = Set<String>()
        for (id, ips) in blocked where policies[id] == .deny { all.formUnion(ips) }
        return all
    }

    func blockedAddresses(for id: String) -> Int { policies[id] == .deny ? (blocked[id]?.count ?? 0) : 0 }

    func applyBlocking() { enforcer.apply(wantedBlocklist) }

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

    /// Chart data for a range: live samples up to an hour, minute buckets re-aggregated beyond that.
    func chartPoints(_ range: TimeRange) -> [TrafficPoint] {
        let cutoff = Date().addingTimeInterval(-range.seconds)
        switch range {
        case .fiveMinutes, .hour:
            return history.filter { $0.date >= cutoff }
        case .day, .week:
            let size: TimeInterval = range == .day ? 1800 : 6 * 3600
            var out: [Date: (Double, Double)] = [:]
            for b in buckets.values where b.minute >= cutoff {
                let key = Date(timeIntervalSince1970: (b.minute.timeIntervalSince1970 / size).rounded(.down) * size)
                let cur = out[key] ?? (0, 0)
                out[key] = (cur.0 + b.rx, cur.1 + b.tx)
            }
            return out.map { TrafficPoint(date: $0.key, rx: $0.value.0, tx: $0.value.1) }.sorted { $0.date < $1.date }
        }
    }

    #if DEBUG
    /// Fake servers for checking the map without sending real addresses anywhere.
    private func installDemoData() {
        myLocation = GeoPoint(coordinate: .init(latitude: 52.52, longitude: 13.405), city: "Berlin", country: "Germany")
        geoEnabled = true
        demo = true
        let places: [(String, String, String, Double, Double)] = [
            ("Google Chrome", "London", "United Kingdom", 51.507, -0.128), ("Google Chrome", "Amsterdam", "Netherlands", 52.37, 4.89),
            ("Telegram", "Frankfurt", "Germany", 50.11, 8.68), ("Telegram", "Paris", "France", 48.857, 2.352),
            ("Steam", "Stockholm", "Sweden", 59.33, 18.07), ("Steam", "Madrid", "Spain", 40.42, -3.70),
        ]
        for (i, d) in places.enumerated() {
            let ident = AppIdentity.resolve(processPath: "/Applications/\(d.0).app/Contents/MacOS/x")
            var e = table[ident.id] ?? AppEntry(identity: ident)
            e.lastActive = Date(); e.totalIn = UInt64(1_000_000 * (i + 1)); e.totalOut = UInt64(100_000 * (i + 1))
            e.remotes.append(RemoteHost(address: "203.0.113.\(i + 1)", host: "demo\(i).example.com", port: 443, proto: "TCP",
                                        geo: GeoPoint(coordinate: .init(latitude: d.3, longitude: d.4), city: d.1, country: d.2)))
            table[ident.id] = e
        }
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
