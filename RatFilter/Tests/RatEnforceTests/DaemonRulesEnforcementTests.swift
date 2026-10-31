import XCTest
@testable import RatEnforce
import RatFilterCore
import RatMonitor

/// The daemon follows rules for one process or one connection itself (`deny-rules.json`): it reads the sockets of
/// the processes they name on every pass and blocks the local ports of those the rules deny. This test process is
/// the "app"; pfctl is never run.
final class DaemonRulesEnforcementTests: XCTestCase {
    let exe = ConnectionSampler.path(of: getpid())
    var app: String { ProcessGrouping.owner(of: exe, responsiblePath: { nil }).ruleKey }

    private func tempDir() throws -> URL {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("rat-enf-rules-\(UUID())")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        addTeardownBlock { try? FileManager.default.removeItem(at: dir) }
        return dir
    }

    /// A UDP socket, bound to an ephemeral port and, given a server, connected to it (UDP sends nothing to connect).
    private func udpSocket(to server: String? = nil, port: UInt16 = 443) throws -> (fd: Int32, port: Int) {
        let fd = socket(AF_INET, SOCK_DGRAM, 0)
        addTeardownBlock { close(fd) }
        var addr = sockaddr_in(); addr.sin_family = sa_family_t(AF_INET); addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        if let server {
            inet_pton(AF_INET, server, &addr.sin_addr)
            addr.sin_port = port.bigEndian
            let r = withUnsafePointer(to: &addr) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.connect(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) } }
            try XCTSkipIf(r != 0, "no route to \(server) here (errno \(errno))")
        } else {
            addr.sin_addr.s_addr = UInt32(0x7f000001).bigEndian
            _ = withUnsafePointer(to: &addr) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) } }
        }
        var bound = sockaddr_in(); var len = socklen_t(MemoryLayout<sockaddr_in>.size)
        _ = withUnsafeMutablePointer(to: &bound) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(fd, $0, &len) } }
        return (fd, Int(UInt16(bigEndian: bound.sin_port)))
    }

    private func daemon(_ dir: URL, rules: DaemonRules, status: String? = nil) throws -> (EnforcerDaemon, () -> [String]) {
        try "".write(to: dir.appendingPathComponent("denied.txt"), atomically: true, encoding: .utf8)
        try rules.encoded().write(to: dir.appendingPathComponent("deny-rules.json"))
        var s = EnforcerDaemon.Settings(deniedFile: dir.appendingPathComponent("denied.txt").path, statusFile: status)
        s.rulesFile = dir.appendingPathComponent("deny-rules.json").path
        s.anchor = "com.apple/rat-unittest"
        var loaded: [String] = []
        let d = EnforcerDaemon(settings: s, run: { _, args, stdin in if args.contains("-f") { loaded.append(stdin ?? "") }; return 0 },
                               capture: { _, args in args == ["-s", "info"] ? "Status: Enabled" : args == ["-s", "rules"] ? "anchor \"com.apple/*\" all" : "" })
        return (d, { loaded })
    }

    func testAProcessDenyBlocksEverySocketOfThatProcess() throws {
        let dir = try tempDir()
        let (_, unconnected) = try udpSocket()
        let (_, connected) = try udpSocket(to: "203.0.113.5")
        let (d, loaded) = try daemon(dir, rules: DaemonRules(rules: [Rule(verdict: .deny, processPath: app, executable: exe, listLevel: .process)]))
        XCTAssertTrue(d.tick(), "a process a deny rule names is read on the fast pass")
        XCTAssertTrue(d.loadedPorts.contains(unconnected))
        XCTAssertTrue(d.loadedPorts.contains(connected))
        XCTAssertTrue(loaded().last?.contains("\(connected)") ?? false)
        XCTAssertTrue(d.deniedPIDs.isEmpty, "not denied as a whole app")
    }

    /// The daemon lists every process only four times a second; a process started in between is noticed on the next
    /// pass from the newest few the kernel lists, and its sockets are cut then.
    func testAProcessStartedBetweenFullScansIsCutOnTheNextPass() throws {
        let dir = try tempDir()
        // pfctl is stubbed, so a rule for nc blocks nothing on this Mac.
        let nc = "/usr/bin/nc"
        let rule = Rule(verdict: .deny, processPath: nc, executable: nc, listLevel: .process)
        let (d, _) = try daemon(dir, rules: DaemonRules(rules: [rule]))
        let t0 = Date()
        XCTAssertTrue(d.tick(now: t0), "a deny rule names a program: passes go on")
        XCTAssertFalse(d.watching, "nc does not run yet: the next pass comes after the standby interval (20 ms)")

        let p = Process()
        p.executableURL = URL(fileURLWithPath: nc)
        p.arguments = ["-u", "203.0.113.5", "443"]
        p.standardInput = Pipe(); p.standardOutput = FileHandle.nullDevice; p.standardError = FileHandle.nullDevice
        try p.run()
        addTeardownBlock { p.terminate(); p.waitUntilExit() }
        var port = 0
        let deadline = Date().addingTimeInterval(5)
        while port == 0, Date() < deadline {
            port = ConnectionSampler.socketFDs(of: p.processIdentifier).lazy.compactMap { ConnectionSampler.connection(pid: p.processIdentifier, fd: $0, processPath: "")?.localPort }.first { $0 != 0 } ?? 0
            if port == 0 { usleep(10_000) }
        }
        try XCTSkipIf(port == 0, "nc opened no socket here")
        XCTAssertTrue(d.tick(now: t0.addingTimeInterval(0.02)), "found without waiting for the next full scan")
        XCTAssertTrue(d.watching, "a watched process runs: passes every 3 ms")
        XCTAssertTrue(d.loadedPorts.contains(port))
    }

    func testAnotherProcessesRuleLeavesThisOneAlone() throws {
        let dir = try tempDir()
        let (_, port) = try udpSocket(to: "203.0.113.5")
        let (d, _) = try daemon(dir, rules: DaemonRules(rules: [Rule(verdict: .deny, processPath: app, executable: app + "/Contents/MacOS/Other Helper", listLevel: .process)]))
        d.tick()
        XCTAssertFalse(d.loadedPorts.contains(port))
    }

    func testAConnectionDenyBlocksOnlyThatConnection() throws {
        let dir = try tempDir()
        let (_, denied) = try udpSocket(to: "203.0.113.5")
        let (_, other) = try udpSocket(to: "203.0.113.6")
        let (_, otherPort) = try udpSocket(to: "203.0.113.5", port: 444)
        let rule = Rule(verdict: .deny, processPath: app, executable: exe, listLevel: .connection, remoteAddress: "203.0.113.5", ports: 443...443, proto: .udp)
        let (d, _) = try daemon(dir, rules: DaemonRules(rules: [rule]))
        XCTAssertTrue(d.tick())
        XCTAssertTrue(d.loadedPorts.contains(denied))
        XCTAssertFalse(d.loadedPorts.contains(other))
        XCTAssertFalse(d.loadedPorts.contains(otherPort))
    }

    /// A rule for a server by name applies once Rat has named the address; the names arrive in the same file.
    func testANameRuleFollowsRatsNames() throws {
        let dir = try tempDir()
        let (_, port) = try udpSocket(to: "203.0.113.7")
        let rule = Rule(verdict: .deny, processPath: app, executable: exe, listLevel: .connection, remoteHost: "ads.example.com", ports: 443...443, proto: .udp)
        let (d, _) = try daemon(dir, rules: DaemonRules(rules: [rule]))
        d.tick()
        XCTAssertFalse(d.loadedPorts.contains(port), "not named yet")
        let file = dir.appendingPathComponent("deny-rules.json")
        try DaemonRules(rules: [rule], names: ["203.0.113.7": "ads.example.com"]).encoded().write(to: file)
        try FileManager.default.setAttributes([.modificationDate: Date().addingTimeInterval(2)], ofItemAtPath: file.path)
        d.tick(now: Date().addingTimeInterval(0.1))
        XCTAssertTrue(d.loadedPorts.contains(port), "judged again when the names change")
    }

    func testStatusReportsRuleCutsAndAFileThatDoesNotParseIsNoRules() throws {
        let dir = try tempDir()
        let statusPath = dir.appendingPathComponent("status.json").path
        let (_, port) = try udpSocket(to: "203.0.113.5")
        let (d, _) = try daemon(dir, rules: DaemonRules(rules: [Rule(verdict: .deny, processPath: app, executable: exe, listLevel: .process)]), status: statusPath)
        d.tick()
        let dec = JSONDecoder(); dec.dateDecodingStrategy = .secondsSince1970
        let st = try dec.decode(EnforcerStatus.self, from: Data(contentsOf: URL(fileURLWithPath: statusPath)))
        XCTAssertEqual(st.ruleDenied?[app]?.processes, 1)
        XCTAssertGreaterThanOrEqual(st.ruleDenied?[app]?.ports ?? 0, 1)
        XCTAssertEqual(st.denyRules, 1)
        XCTAssertTrue(st.deniedApps.isEmpty)

        let file = dir.appendingPathComponent("deny-rules.json")
        try "{ not json".write(to: file, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.modificationDate: Date().addingTimeInterval(2)], ofItemAtPath: file.path)
        XCTAssertFalse(d.tick(now: Date().addingTimeInterval(0.1)), "nothing to watch")
        // The port stays blocked for `portHold` (packets in flight), then goes.
        d.tick(now: Date().addingTimeInterval(10))
        XCTAssertFalse(d.loadedPorts.contains(port))
    }

    /// An allow rule alone never makes the daemon read anything.
    func testOnlyAllowRulesWatchNothing() throws {
        let dir = try tempDir()
        let (d, _) = try daemon(dir, rules: DaemonRules(rules: [Rule(verdict: .allow, processPath: app, executable: exe, listLevel: .process)]))
        XCTAssertFalse(d.tick())
        XCTAssertTrue(d.loadedPorts.isEmpty)
    }

    func testTheToolReadsDenyRulesNextToTheDenyList() {
        // `runEnforcerTool` never returns; the default it uses is spelled out here so a change to it is a change here.
        let denied = "/Users/me/Library/Application Support/com.imanmontajabi.Rat/denied-apps.txt"
        XCTAssertEqual(((denied as NSString).deletingLastPathComponent as NSString).appendingPathComponent("deny-rules.json"),
                       "/Users/me/Library/Application Support/com.imanmontajabi.Rat/deny-rules.json")
    }
}

/// "Only through a VPN" (#45): the daemon works out per socket whether it leaves outside a tunnel and cuts it then,
/// on the fast pass. This test process is the app; which of its sockets is cut follows this Mac's routes now.
final class VPNOnlyEnforcementTests: XCTestCase {
    let exe = ConnectionSampler.path(of: getpid())
    var app: String { ProcessGrouping.owner(of: exe, responsiblePath: { nil }).ruleKey }

    private func udp(to server: String?) throws -> (port: Int, local: String) {
        let fd = socket(AF_INET, SOCK_DGRAM, 0)
        addTeardownBlock { close(fd) }
        var addr = sockaddr_in(); addr.sin_family = sa_family_t(AF_INET); addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        if let server {
            inet_pton(AF_INET, server, &addr.sin_addr); addr.sin_port = UInt16(443).bigEndian
            let r = withUnsafePointer(to: &addr) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.connect(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) } }
            try XCTSkipIf(r != 0, "no route to \(server) here (errno \(errno))")
        } else {
            addr.sin_addr.s_addr = UInt32(0x7f000001).bigEndian
            _ = withUnsafePointer(to: &addr) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) } }
        }
        var bound = sockaddr_in(); var len = socklen_t(MemoryLayout<sockaddr_in>.size)
        _ = withUnsafeMutablePointer(to: &bound) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(fd, $0, &len) } }
        var buf = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
        let local = inet_ntop(AF_INET, &bound.sin_addr, &buf, socklen_t(buf.count)).map { String(cString: $0) } ?? ""
        return (Int(UInt16(bigEndian: bound.sin_port)), local)
    }

    func testTheDaemonCutsWhatLeavesOutsideTheTunnel() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("rat-enf-vpn-\(UUID())")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        addTeardownBlock { try? FileManager.default.removeItem(at: dir) }
        let internet = try udp(to: "203.0.113.5")
        let loopback = try udp(to: nil)
        try "".write(to: dir.appendingPathComponent("denied.txt"), atomically: true, encoding: .utf8)
        let rules = DaemonRules(rules: [Rule(verdict: .deny, processPath: app, requireVPN: true), Rule(verdict: .allow, processPath: app, listLevel: .app)])
        try rules.encoded().write(to: dir.appendingPathComponent("deny-rules.json"))
        var s = EnforcerDaemon.Settings(deniedFile: dir.appendingPathComponent("denied.txt").path, statusFile: nil)
        s.rulesFile = dir.appendingPathComponent("deny-rules.json").path
        s.anchor = "com.apple/rat-unittest"
        let d = EnforcerDaemon(settings: s, run: { _, _, _ in 0 },
                               capture: { _, args in args == ["-s", "info"] ? "Status: Enabled" : args == ["-s", "rules"] ? "anchor \"com.apple/*\" all" : "" })
        XCTAssertTrue(d.tick())
        let throughTunnel = NetworkRoutes.tunnelAddresses()[internet.local] != nil
        XCTAssertEqual(d.loadedPorts.contains(internet.port), !throughTunnel,
                       "a socket from \(internet.local) is cut unless that is a tunnel's address (tunnels: \(NetworkRoutes.tunnelAddresses()))")
        XCTAssertFalse(d.loadedPorts.contains(loopback.port), "bound to loopback: never cut")
        XCTAssertTrue(d.deniedPIDs.isEmpty, "never the whole app")
    }
}
