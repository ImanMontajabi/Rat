import XCTest
import Darwin
@testable import RatEnforce
import RatFilterCore
import RatMonitor

/// Time and memory budgets for the helper's pass: it runs every 3 ms while a denied or watched process runs, so a
/// pass must cost a small part of that, a full scan of every process (four times a second) well under its interval,
/// and nothing may grow while sockets come and go. This test process is the denied program; pfctl is never run. The
/// budgets are several times what a Debug build takes on an M-series Mac.
final class DaemonPerformanceTests: XCTestCase {
    let exe = ConnectionSampler.path(of: getpid())
    var app: String { ProcessGrouping.owner(of: exe, responsiblePath: { nil }).ruleKey }

    static func mallocMB() -> Double {
        var s = malloc_statistics_t()
        malloc_zone_statistics(nil, &s)
        return Double(s.size_in_use) / 1_048_576
    }

    private func tempDir() throws -> URL {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("rat-enf-perf-\(UUID())")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        addTeardownBlock { try? FileManager.default.removeItem(at: dir) }
        return dir
    }

    /// A UDP socket on a loopback ephemeral port (`bind` gives it its port; nothing is sent).
    private func udpSocket() -> Int32 {
        let fd = socket(AF_INET, SOCK_DGRAM, 0)
        var addr = sockaddr_in(); addr.sin_family = sa_family_t(AF_INET); addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        addr.sin_addr.s_addr = UInt32(0x7f000001).bigEndian
        _ = withUnsafePointer(to: &addr) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) } }
        return fd
    }

    private var sockets: [Int32] = []
    override func tearDown() { sockets.forEach { close($0) }; sockets = []; super.tearDown() }

    private func daemon(_ dir: URL, denied: String = "", rules: DaemonRules = DaemonRules(rules: [])) throws -> EnforcerDaemon {
        try denied.write(to: dir.appendingPathComponent("denied.txt"), atomically: true, encoding: .utf8)
        try rules.encoded().write(to: dir.appendingPathComponent("deny-rules.json"))
        var s = EnforcerDaemon.Settings(deniedFile: dir.appendingPathComponent("denied.txt").path, statusFile: dir.appendingPathComponent("status.json").path)
        s.rulesFile = dir.appendingPathComponent("deny-rules.json").path
        s.anchor = "com.apple/rat-unittest"
        return EnforcerDaemon(settings: s, run: { _, _, _ in 0 },
                              capture: { _, args in args == ["-s", "info"] ? "Status: Enabled" : args == ["-s", "rules"] ? "anchor \"com.apple/*\" all" : "" })
    }

    /// The daemon's clock: passes 3 ms apart, whatever they take here.
    private var now = Date()
    private var lastFull = Date()

    /// Passes 3 ms apart, as while a denied process runs; every 84th is a full scan (0.25 s). Returns the average
    /// fast pass and the average full scan, in seconds.
    @discardableResult
    private func passes(_ d: EnforcerDaemon, count: Int) -> (fast: Double, full: Double) {
        var fast: [Double] = [], full: [Double] = []
        for _ in 0..<count {
            now += 0.003
            let isFull = now.timeIntervalSince(lastFull) >= 0.25
            if isFull { lastFull = now }
            d.tick(now: now)
            if isFull { full.append(d.lastTickDuration) } else { fast.append(d.lastTickDuration) }
        }
        func avg(_ a: [Double]) -> Double { a.isEmpty ? 0 : a.reduce(0, +) / Double(a.count) }
        return (avg(fast), avg(full))
    }

    /// A process younger than a second has its path read on every pass (so an exec is noticed); at the daemon's
    /// start that is only the processes the kernel started in the last second, not every process on the Mac, so its
    /// first 1.2 s take a small part of that time too.
    private func steady(_ d: EnforcerDaemon, _ what: String) -> (fast: Double, full: Double) {
        let t0 = Date()
        passes(d, count: 400)   // 1.2 s of the daemon's time
        let warmUp = Date().timeIntervalSince(t0)
        XCTAssertLessThan(warmUp, 0.6, "the first 1.2 s at most half busy")
        let t = passes(d, count: 1_000)
        print("helper, \(what), 64 sockets: fast pass \(String(format: "%.3f", t.fast * 1000)) ms, full scan \(String(format: "%.2f", t.full * 1000)) ms, first 1.2 s \(String(format: "%.0f", warmUp * 1000)) ms")
        return t
    }

    func testAPassForAProcessDenyFitsItsBudget() throws {
        sockets = (0..<64).map { _ in udpSocket() }
        let d = try daemon(try tempDir(), rules: DaemonRules(rules: [Rule(verdict: .deny, processPath: app, executable: exe, listLevel: .process)]))
        XCTAssertTrue(d.tick(now: now))
        XCTAssertGreaterThanOrEqual(d.loadedPorts.count, 64, "every socket of the process is cut")
        let t = steady(d, "process deny")
        XCTAssertLessThan(t.fast, 0.0015, "half the 3 ms interval at most")
        XCTAssertLessThan(t.full, 0.05, "a full scan of every process")
    }

    func testAPassForAWholeAppDenyFitsItsBudget() throws {
        sockets = (0..<64).map { _ in udpSocket() }
        let d = try daemon(try tempDir(), denied: exe + "\n")
        XCTAssertTrue(d.tick(now: now))
        XCTAssertTrue(d.deniedPIDs.contains(getpid()))
        let t = steady(d, "whole-app deny")
        XCTAssertLessThan(t.fast, 0.0015)
        XCTAssertLessThan(t.full, 0.05)
    }

    /// 6,000 passes (18 s of the helper's time) while a sixteenth of the sockets close and others open every 100
    /// passes: what the helper keeps per port or socket goes with it.
    func testSocketsThatComeAndGoLeaveNothingBehind() throws {
        sockets = (0..<64).map { _ in udpSocket() }
        let d = try daemon(try tempDir(), rules: DaemonRules(rules: [Rule(verdict: .deny, processPath: app, executable: exe, listLevel: .process)]))
        func churn(_ rounds: Int) {
            for _ in 0..<rounds {
                for i in 0..<4 { close(sockets[i]); sockets[i] = udpSocket() }
                sockets.append(contentsOf: sockets.prefix(4)); sockets.removeFirst(4)
                _ = autoreleasepool { passes(d, count: 100) }
            }
        }
        churn(10)
        let settled = Self.mallocMB()
        churn(60)
        let grown = Self.mallocMB() - settled
        print("helper malloc after 6,000 passes with sockets coming and going: \(String(format: "%+.2f", grown)) MB")
        XCTAssertGreaterThanOrEqual(d.loadedPorts.count, 64)
        XCTAssertLessThan(grown, 2, "the helper's memory stays flat (it runs for weeks)")
    }
}
