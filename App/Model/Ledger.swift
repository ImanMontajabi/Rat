import SwiftUI
import CoreLocation
import RatMonitor
import os

private let logger = Logger(subsystem: "com.imanmontajabi.Rat", category: "ledger")

enum Policy: String { case allow, deny }

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

struct TrafficPoint: Identifiable { let id = UUID(); let date: Date; let rx: Double; let tx: Double }

@MainActor
final class Ledger: ObservableObject {
    @Published var apps: [AppEntry] = []
    @Published var history: [TrafficPoint] = []
    @Published var sessionIn: UInt64 = 0
    @Published var sessionOut: UInt64 = 0
    @Published var myLocation: GeoPoint?
    @Published var policies: [String: Policy] = [:] { didSet { savePolicies() } }
    @Published var geoEnabled = UserDefaults.standard.bool(forKey: "geoLookupEnabled") {
        didSet { UserDefaults.standard.set(geoEnabled, forKey: "geoLookupEnabled"); if geoEnabled { Task { await resolveGeo() } } }
    }

    private let geo = GeoService()
    private let names = HostNames()
    private var previous: [Int32: TrafficCounter] = [:]
    private var table: [String: AppEntry] = [:]
    private var running = false

    init() {
        if let raw = UserDefaults.standard.dictionary(forKey: "policies") as? [String: String] {
            policies = raw.compactMapValues(Policy.init(rawValue:))
        }
    }

    private func savePolicies() {
        UserDefaults.standard.set(policies.mapValues(\.rawValue), forKey: "policies")
    }

    func start() {
        guard !running else { return }
        running = true
        logger.notice("ledger started")
        Task { await loop() }
    }

    private func loop() async {
        while running {
            let (conns, traffic) = await Task.detached(priority: .utility) { (ConnectionSampler.sample(), TrafficSampler.sample()) }.value
            await ingest(conns, traffic)
            if geoEnabled { await resolveGeo() }
            try? await Task.sleep(for: .seconds(1.5))
        }
    }

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
        if history.count > 3600 { history.removeFirst(history.count - 3600) }

        for id in table.keys {
            var e = table[id]!
            let rx = rxByApp[id] ?? 0, tx = txByApp[id] ?? 0
            e.rates.append((rx, tx)); if e.rates.count > 14 { e.rates.removeFirst() }
            if rx + tx > 0 { e.lastActive = now }
            e.listening = perApp[id]?.listening ?? 0
            var remotes: [RemoteHost] = []
            var seen = Set<String>()
            for c in perApp[id]?.conns ?? [] where seen.insert("\(c.remoteAddress):\(c.remotePort)").inserted {
                let host = await names.name(for: c.remoteAddress)
                let old = e.remotes.first { $0.address == c.remoteAddress }
                remotes.append(RemoteHost(address: c.remoteAddress, host: host, port: c.remotePort, proto: c.proto.rawValue.uppercased(), geo: old?.geo))
            }
            e.remotes = remotes
            table[id] = e
        }
        apps = Array(table.values)
    }

    private func resolveGeo() async {
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

    // MARK: derived

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

    func setPolicy(_ p: Policy?, for id: String) { policies[id] = p }
}

func formatBytes(_ n: UInt64) -> String {
    ByteCountFormatter.string(fromByteCount: Int64(n), countStyle: .file)
}
