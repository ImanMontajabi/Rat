import XCTest
import Darwin
import RatMonitor
@testable import Rat

/// Time and memory budgets for the ledger's pass (every 1.5 s): a busy Mac's sockets judged and grouped well
/// within the interval, and nothing growing without bound while sockets come and go. The budgets are several times
/// what a Debug build takes on an M-series Mac, so a slower CI runner passes and a regression of that order fails.
@MainActor
final class PerformanceBudgetTests: XCTestCase {
    /// The process's physical footprint (what Activity Monitor shows as Memory), in MB.
    static func footprintMB() -> Double {
        var info = task_vm_info_data_t()
        var count = mach_msg_type_number_t(MemoryLayout<task_vm_info_data_t>.size / MemoryLayout<integer_t>.size)
        let r = withUnsafeMutablePointer(to: &info) { $0.withMemoryRebound(to: integer_t.self, capacity: Int(count)) { task_info(mach_task_self_, task_flavor_t(TASK_VM_INFO), $0, &count) } }
        return r == KERN_SUCCESS ? Double(info.phys_footprint) / 1_048_576 : 0
    }

    /// Bytes the process holds in malloc, in MB: what the ledger keeps, without the test host's window drawing
    /// (which the footprint counts too).
    static func mallocMB() -> Double {
        var s = malloc_statistics_t()
        malloc_zone_statistics(nil, &s)
        return Double(s.size_in_use) / 1_048_576
    }

    private func ledger() throws -> Ledger {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("rat-perf-\(UUID())")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        addTeardownBlock { try? FileManager.default.removeItem(at: dir) }
        return Ledger(directory: dir, helperInstalled: false, names: HostNames(resolve: { _ in nil }))
    }

    /// 200 apps with 10 sockets each (a busy Mac has about 1,000), each with its byte counters. `round` changes the
    /// local ports, as when connections close and others open.
    private func load(round: Int = 0) -> ([ObservedConnection], [FlowCounter]) {
        var conns: [ObservedConnection] = [], flows: [FlowCounter] = []
        for app in 0..<200 {
            let pid = Int32(10_000 + app)
            let path = "/Applications/Perf\(app).app/Contents/MacOS/Perf\(app)"
            for s in 0..<10 {
                let port = 20_000 + (app * 10 + s + round * 2_000) % 40_000
                let remote = "198.51.\(app % 100).\(s + 1)"
                conns.append(ObservedConnection(pid: pid, processPath: path, proto: s % 3 == 0 ? .udp : .tcp, remoteAddress: remote, remotePort: 443,
                                                localPort: port, tcpState: s % 3 == 0 ? nil : "ESTABLISHED"))
                flows.append(FlowCounter(pid: pid, proto: s % 3 == 0 ? .udp : .tcp, localPort: port, remoteAddress: remote, remotePort: 443,
                                         bytesIn: UInt64(round * 10_000 + s), bytesOut: UInt64(round * 1_000)))
            }
        }
        return (conns, flows)
    }

    func testALedgerPassOfTwoThousandSocketsFitsItsBudget() async throws {
        let l = try ledger()
        let (conns, flows) = load()
        await l.ingest(conns, [], flows: flows)   // first pass: identities, signatures
        var times: [Double] = []
        for _ in 0..<10 {
            let t0 = Date()
            await l.ingest(conns, [], flows: flows)
            times.append(Date().timeIntervalSince(t0))
        }
        let average = times.reduce(0, +) / Double(times.count)
        print("ledger pass, 2,000 sockets: average \(String(format: "%.1f", average * 1000)) ms, worst \(String(format: "%.1f", (times.max() ?? 0) * 1000)) ms")
        XCTAssertEqual(l.apps.count, 200)
        XCTAssertLessThan(average, 0.25, "a pass must stay far inside its 1.5 s interval")
    }

    /// Sockets come and go for 150 passes (a fresh set of local ports every pass): what the ledger keeps per socket
    /// is dropped with it, and its memory stops growing. Each pass is a job of its own, as on the app's timer: a pass
    /// leaves about 1.7 MB of autoreleased temporaries that go when it ends, and 130 passes in one job would hold
    /// them all.
    func testSocketsThatComeAndGoLeaveNothingBehind() async throws {
        let l = try ledger()
        for round in 0..<20 { let (c, f) = load(round: round); await l.ingest(c, [], flows: f); try await Task.sleep(for: .milliseconds(5)) }
        try await Task.sleep(for: .milliseconds(300))
        let settled = Self.mallocMB()
        for round in 20..<150 { let (c, f) = load(round: round); await l.ingest(c, [], flows: f); try await Task.sleep(for: .milliseconds(5)) }
        try await Task.sleep(for: .milliseconds(300))
        let grown = Self.mallocMB() - settled
        print("malloc after 130 more passes with fresh sockets: +\(String(format: "%.1f", grown)) MB")
        XCTAssertLessThanOrEqual(l.streams.count, 2_000, "one entry per open socket at most")
        XCTAssertLessThan(grown, 15, "nothing grows per pass (2,000 sockets: about 0.4 MB in 130 passes)")
    }

    /// The map's graph is rebuilt on every pass for every listed connection.
    func testTheMapGraphOfTwoThousandConnectionsFitsItsBudget() async throws {
        let l = try ledger()
        let (conns, flows) = load()
        await l.ingest(conns, [], flows: flows)
        // Place every connection somewhere (the test has no GeoIP lookups of its own).
        let apps = l.apps.map { a -> AppEntry in
            var a = a
            a.remotes = a.remotes.enumerated().map { i, r in
                var r = r
                r.geo = GeoPoint(coordinate: .init(latitude: Double(i % 60), longitude: Double(i * 7 % 300) - 150), city: "C\(i % 60)", country: "X")
                r.rateIn = Double(i * 1000)
                return r
            }
            return a
        }
        let me = GeoPoint(coordinate: .init(latitude: 52.5, longitude: 13.4), city: "Berlin", country: "Germany")
        let t0 = Date()
        for _ in 0..<10 { _ = MapPane.graph(apps: apps, selection: nil, filter: MonitorFilter(), me: me) }
        let average = Date().timeIntervalSince(t0) / 10
        print("map graph, 2,000 connections: average \(String(format: "%.1f", average * 1000)) ms")
        XCTAssertLessThan(average, 0.1)
    }
}
