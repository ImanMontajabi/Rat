import XCTest
import Darwin
@testable import RatEnforce
import RatFilterCore
import RatMonitor

/// Time and memory budgets for the helper's pass: it runs every 3 ms while a denied or watched process runs, so a
/// pass must cost a small part of that, a full scan of every process (four times a second) well under its interval,
/// and nothing may grow while sockets come and go. This test process is the denied program; pfctl is never run. The
/// budgets are several times what a Debug build takes on an M-series Mac. Passes are timed by this thread's CPU clock,
/// the work a pass does (it all runs on the calling thread): a shared CI machine that takes the thread away for a
/// while made the wall-clock average of the same code anything from 0.3 to 2.3 ms.
final class DaemonPerformanceTests: XCTestCase {
    let exe = ConnectionSampler.path(of: getpid())
    var app: String { ProcessGrouping.owner(of: exe, responsiblePath: { nil }).ruleKey }

    /// CPU time this thread has used, in seconds.
    static func threadCPU() -> Double { Double(clock_gettime_nsec_np(CLOCK_THREAD_CPUTIME_ID)) / 1e9 }

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
    /// fast pass and the average full scan, in seconds of CPU time.
    @discardableResult
    private func passes(_ d: EnforcerDaemon, count: Int) -> (fast: Double, full: Double) {
        var fast: [Double] = [], full: [Double] = []
        for _ in 0..<count {
            now += 0.003
            let isFull = now.timeIntervalSince(lastFull) >= 0.25
            if isFull { lastFull = now }
            let c0 = Self.threadCPU()
            d.tick(now: now)
            let cpu = Self.threadCPU() - c0
            if isFull { full.append(cpu) } else { fast.append(cpu) }
        }
        func avg(_ a: [Double]) -> Double { a.isEmpty ? 0 : a.reduce(0, +) / Double(a.count) }
        return (avg(fast), avg(full))
    }

    /// A process younger than a second has its path read on every pass (so an exec is noticed); at the daemon's
    /// start that is only the processes the kernel started in the last second, not every process on the Mac, so its
    /// first 1.2 s take a small part of that time too.
    private func steady(_ d: EnforcerDaemon, _ what: String) -> (fast: Double, full: Double) {
        let t0 = Date(), c0 = Self.threadCPU()
        passes(d, count: 400)   // 1.2 s of the daemon's time
        let warmUp = Self.threadCPU() - c0, wall = Date().timeIntervalSince(t0)
        XCTAssertLessThan(warmUp, 0.6, "the first 1.2 s at most half busy")
        let t = passes(d, count: 1_000)
        print("helper, \(what), 64 sockets (CPU): fast pass \(String(format: "%.3f", t.fast * 1000)) ms, full scan \(String(format: "%.2f", t.full * 1000)) ms, first 1.2 s \(String(format: "%.0f", warmUp * 1000)) ms (\(String(format: "%.0f", wall * 1000)) ms wall)")
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

    /// The pass right after the deny list changes loads the denied process's ports without first doing work for
    /// every process on the Mac (reading the start time of all of them took 15 ms there, and a stream through a
    /// local proxy kept filling curl's buffer meanwhile: `verify-blocking.sh` phase 3).
    func testADenyIsLoadedWithoutWorkForEveryProcess() throws {
        sockets = (0..<8).map { _ in udpSocket() }
        let dir = try tempDir()
        let denied = dir.appendingPathComponent("denied.txt")
        try "/usr/bin/rat-test-not-running\n".write(to: denied, atomically: true, encoding: .utf8)
        try DaemonRules(rules: []).encoded().write(to: dir.appendingPathComponent("deny-rules.json"))
        var s = EnforcerDaemon.Settings(deniedFile: denied.path)
        s.rulesFile = dir.appendingPathComponent("deny-rules.json").path
        s.anchor = "com.apple/rat-unittest"
        var loadedAt: Double?, agesAtLoad: Int?
        weak var daemon: EnforcerDaemon?
        let d = EnforcerDaemon(settings: s, run: { _, args, stdin in
            if args.contains("-f"), loadedAt == nil, stdin?.contains("block") ?? false { loadedAt = Self.threadCPU(); agesAtLoad = daemon?.agesRead }
            return 0
        }, capture: { _, args in args == ["-s", "info"] ? "Status: Enabled" : args == ["-s", "rules"] ? "anchor \"com.apple/*\" all" : "" })
        daemon = d
        passes(d, count: 400)   // every process known and aged, as on a Mac where the daemon has run for a while
        XCTAssertTrue(d.loadedPorts.isEmpty)
        let agesBefore = d.agesRead

        try (exe + "\n").write(to: denied, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.modificationDate: now.addingTimeInterval(1)], ofItemAtPath: denied.path)
        now += 0.06   // past the file check interval
        let c0 = Self.threadCPU()
        d.tick(now: now)
        let latency = try XCTUnwrap(loadedAt, "the denied process's ports were loaded on that pass") - c0
        print("helper, deny list changed: ports loaded (CPU) \(String(format: "%.2f", latency * 1000)) ms into the pass, pass \(String(format: "%.2f", d.lastTickDuration * 1000)) ms")
        XCTAssertTrue(d.deniedPIDs.contains(getpid()))
        XCTAssertGreaterThanOrEqual(d.loadedPorts.count, 8)
        XCTAssertEqual(agesAtLoad, agesBefore, "no start time read before the ports are loaded")
        XCTAssertGreaterThan(d.agesRead - agesBefore, 50, "every process met again is aged after the load, on the same pass")
        XCTAssertLessThan(latency, 0.05)
    }

    /// The same for a rule for one process (`deny-rules.json`): the pass after the rules change judges every
    /// process against them again, then loads the named process's ports, and no more.
    func testAProcessRuleIsLoadedWithoutWorkForEveryProcess() throws {
        sockets = (0..<8).map { _ in udpSocket() }
        let dir = try tempDir()
        let rulesFile = dir.appendingPathComponent("deny-rules.json")
        try "".write(to: dir.appendingPathComponent("denied.txt"), atomically: true, encoding: .utf8)
        try DaemonRules(rules: [Rule(verdict: .deny, processPath: "/usr/bin/rat-test-not-running", executable: "/usr/bin/rat-test-not-running", listLevel: .process)]).encoded().write(to: rulesFile)
        var s = EnforcerDaemon.Settings(deniedFile: dir.appendingPathComponent("denied.txt").path)
        s.rulesFile = rulesFile.path
        s.anchor = "com.apple/rat-unittest"
        var loadedAt: Double?, agesAtLoad: Int?
        weak var daemon: EnforcerDaemon?
        let d = EnforcerDaemon(settings: s, run: { _, args, stdin in
            if args.contains("-f"), loadedAt == nil, stdin?.contains("block") ?? false { loadedAt = Self.threadCPU(); agesAtLoad = daemon?.agesRead }
            return 0
        }, capture: { _, args in args == ["-s", "info"] ? "Status: Enabled" : args == ["-s", "rules"] ? "anchor \"com.apple/*\" all" : "" })
        daemon = d
        passes(d, count: 400)
        XCTAssertTrue(d.loadedPorts.isEmpty)
        let agesBefore = d.agesRead

        try DaemonRules(rules: [Rule(verdict: .deny, processPath: app, executable: exe, listLevel: .process)]).encoded().write(to: rulesFile, options: .atomic)
        d.filesChanged()
        now += 0.001
        let c0 = Self.threadCPU()
        d.tick(now: now)
        let latency = try XCTUnwrap(loadedAt, "the named process's ports were loaded on that pass") - c0
        print("helper, process rule added: ports loaded (CPU) \(String(format: "%.2f", latency * 1000)) ms into the pass, pass \(String(format: "%.2f", d.lastTickDuration * 1000)) ms")
        XCTAssertGreaterThanOrEqual(d.loadedPorts.count, 8)
        XCTAssertEqual(agesAtLoad, agesBefore, "no start time read before the ports are loaded")
        XCTAssertLessThan(latency, 0.05)
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
