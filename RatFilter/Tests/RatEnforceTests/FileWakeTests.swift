import XCTest
import Darwin
@testable import RatEnforce
import RatMonitor

/// The daemon wakes as soon as a file Rat hands it changes, however it is written, instead of after its idle sleep.
final class FileWakeTests: XCTestCase {
    private func tempDir() throws -> URL {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("rat-wake-\(UUID())")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        addTeardownBlock { try? FileManager.default.removeItem(at: dir) }
        return dir
    }

    /// Writes after a short delay on another thread, and returns how long `wait` took to wake.
    private func woke(_ wake: FileWake, after write: @escaping () -> Void) -> TimeInterval? {
        DispatchQueue.global().asyncAfter(deadline: .now() + 0.05, execute: write)
        let t0 = Date()
        return wake.wait(2) ? Date().timeIntervalSince(t0) : nil
    }

    func testEveryWayOfWritingWakesAtOnce() throws {
        let dir = try tempDir()
        let file = dir.appendingPathComponent("denied-apps.txt")
        try "".write(to: file, atomically: true, encoding: .utf8)
        let wake = FileWake(files: [file.path, dir.appendingPathComponent("deny-rules.json").path])
        XCTAssertEqual(wake.watchedCount, 2, "the folder and the file that exists")
        XCTAssertFalse(wake.wait(0.1), "nothing changed: the full sleep")

        let inPlace = try XCTUnwrap(woke(wake) { _ = try? FileHandle(forWritingTo: file).write(contentsOf: Data("/usr/bin/curl\n".utf8)) }, "echo … > file")
        let replaced = try XCTUnwrap(woke(wake) { try? "/usr/bin/nc\n".write(to: file, atomically: true, encoding: .utf8) }, "Rat's atomic write")
        let afterReplace = try XCTUnwrap(woke(wake) { _ = try? FileHandle(forWritingTo: file).write(contentsOf: Data("x".utf8)) }, "the new file is watched too")
        let created = try XCTUnwrap(woke(wake) { try? Data("{}".utf8).write(to: dir.appendingPathComponent("deny-rules.json")) }, "a file that did not exist")
        for t in [inPlace, replaced, afterReplace, created] { XCTAssertLessThan(t, 0.5, "woken by the change, not by the 2 s timeout") }
        // A write can wake more than once (an atomic write creates its temporary file, then renames it); once the
        // writes stop, so do the wakeups: watching the files again does not wake the watcher itself.
        var extra = 0
        while wake.wait(0.2), extra < 10 { extra += 1 }
        XCTAssertLessThan(extra, 10)
        XCTAssertFalse(wake.wait(0.3), "quiet once nothing is written")
    }

    private func openFDs() -> Int {
        let n = proc_pidinfo(getpid(), PROC_PIDLISTFDS, 0, nil, 0)
        return Int(n) / MemoryLayout<proc_fdinfo>.stride
    }

    /// Rat rewrites its files on every change; each replacement opens the new file's source and closes the old one.
    func testReplacingTheFilesLeaksNoDescriptors() throws {
        let dir = try tempDir()
        let file = dir.appendingPathComponent("denied-ports.txt")
        try "".write(to: file, atomically: true, encoding: .utf8)
        let wake = FileWake(files: [file.path])
        for i in 0..<20 { try "\(i)".write(to: file, atomically: true, encoding: .utf8); _ = wake.wait(0.5) }
        let before = openFDs()
        for i in 0..<200 { try "\(i)".write(to: file, atomically: true, encoding: .utf8); _ = wake.wait(0.5) }
        XCTAssertLessThanOrEqual(openFDs(), before + 2, "a helper that runs for weeks keeps the same descriptors")
    }

    /// A deny written while nothing is denied (the daemon in its 1 s idle sleep) is enforced at once, on the
    /// passes the write wakes: the wakeup also skips the 50 ms between file checks. What is timed is the wakeup; the
    /// passes after it cost what `DaemonPerformanceTests` holds (30-40 ms of wall time each on a busy CI machine).
    func testADenyWrittenWhileIdleIsEnforcedAtOnce() throws {
        let dir = try tempDir()
        let denied = dir.appendingPathComponent("denied.txt")
        try "".write(to: denied, atomically: true, encoding: .utf8)
        let fd = socket(AF_INET, SOCK_DGRAM, 0)
        defer { close(fd) }
        var addr = sockaddr_in(); addr.sin_family = sa_family_t(AF_INET); addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        addr.sin_addr.s_addr = UInt32(0x7f000001).bigEndian
        _ = withUnsafePointer(to: &addr) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) } }
        var s = EnforcerDaemon.Settings(deniedFile: denied.path)
        s.anchor = "com.apple/rat-unittest"
        let d = EnforcerDaemon(settings: s, run: { _, _, _ in 0 },
                               capture: { _, args in args == ["-s", "info"] ? "Status: Enabled" : args == ["-s", "rules"] ? "anchor \"com.apple/*\" all" : "" })
        let wake = FileWake(files: [denied.path])
        let now = Date()
        XCTAssertFalse(d.tick(now: now), "nothing denied: the daemon sleeps")
        XCTAssertEqual(d.idleSleep(wake), 1, "1 s, since a change to the file wakes it")

        // The loop's steps: sleep (here at most the idle 1 s) until woken, pass, again. The daemon's own clock
        // moves 1 ms a pass, inside the 50 ms between file checks, so only the wakeup makes it read the file.
        let lock = NSLock()
        var writeStarted: Date?
        DispatchQueue.global().asyncAfter(deadline: .now() + 0.05) {
            lock.withLock { writeStarted = Date() }
            try? (ConnectionSampler.path(of: getpid()) + "\n").write(to: denied, atomically: true, encoding: .utf8)
        }
        var passes = 0, clock = now, wokeAt: Date?, woken = false
        while d.loadedPorts.isEmpty, passes < 20 {
            woken = wake.wait(d.idleSleep(wake))
            if woken { wokeAt = Date(); d.filesChanged() }
            clock += 0.001; passes += 1
            d.tick(now: clock)
        }
        XCTAssertTrue(d.deniedPIDs.contains(getpid()))
        XCTAssertFalse(d.loadedPorts.isEmpty, "its socket's port is loaded")
        XCTAssertTrue(woken, "on the pass a wakeup started, not after the 1 s idle sleep")
        let wrote = try XCTUnwrap(lock.withLock { writeStarted })
        let latency = try XCTUnwrap(wokeAt, "woken by the write").timeIntervalSince(wrote)
        print("helper, deny written while idle: woken \(String(format: "%.1f", latency * 1000)) ms after the write, ports loaded \(String(format: "%.1f", Date().timeIntervalSince(wrote) * 1000)) ms after it, \(passes) passes")
        XCTAssertLessThan(latency, 0.1, "woken by the write itself")
    }

    /// The 1 s idle sleep needs every folder watched: a folder that cannot be opened leaves only the timed sleep, so
    /// the daemon keeps waking every 0.25 s for it.
    func testTheLongIdleSleepNeedsEveryFolderWatched() throws {
        let dir = try tempDir()
        let file = dir.appendingPathComponent("denied.txt").path
        let missing = dir.appendingPathComponent("gone/deny-rules.json").path
        let d = EnforcerDaemon(settings: .init(deniedFile: file), run: { _, _, _ in 0 }, capture: { _, _ in "" })
        let watched = FileWake(files: [file, dir.appendingPathComponent("denied-ports.txt").path])
        XCTAssertTrue(watched.watchesFolders)
        XCTAssertEqual(d.idleSleep(watched), 1)
        let partly = FileWake(files: [file, missing])
        XCTAssertFalse(partly.watchesFolders)
        XCTAssertEqual(d.idleSleep(partly), 0.25)
        XCTAssertFalse(FileWake(files: []).watchesFolders)
    }
}
