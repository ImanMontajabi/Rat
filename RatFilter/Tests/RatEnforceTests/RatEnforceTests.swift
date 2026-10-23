import XCTest
@testable import RatEnforce
import RatMonitor

final class RatEnforceTests: XCTestCase {
    func testDeniedAppMatching() {
        let d = DeniedApps(text: "/Applications/Google Chrome.app\n/Users/me/Steam.AppBundle\nrelative/ignored\n/usr/bin/curl\n")
        XCTAssertEqual(d.paths.count, 3)
        XCTAssertTrue(d.matches(path: "/Applications/Google Chrome.app/Contents/Frameworks/X/Google Chrome Helper (Renderer).app/Contents/MacOS/h", responsiblePath: { nil }))
        XCTAssertTrue(d.matches(path: "/Users/me/Steam.AppBundle/Steam/Contents/MacOS/steam_osx", responsiblePath: { nil }))
        XCTAssertTrue(d.matches(path: "/usr/bin/curl", responsiblePath: { nil }))
        XCTAssertFalse(d.matches(path: "/Applications/Google Chrome.app.evil/x", responsiblePath: { nil }))
        XCTAssertFalse(d.matches(path: "/usr/bin/curlx", responsiblePath: { nil }))
    }

    func testWebKitNetworkingFollowsResponsibleApp() {
        let d = DeniedApps(text: "/Applications/Safari.app\n")
        let xpc = "/System/Library/Frameworks/WebKit.framework/Versions/A/XPCServices/com.apple.WebKit.Networking.xpc/Contents/MacOS/com.apple.WebKit.Networking"
        XCTAssertTrue(d.matches(path: xpc, responsiblePath: { "/Applications/Safari.app/Contents/MacOS/Safari" }))
        XCTAssertFalse(d.matches(path: xpc, responsiblePath: { "/Applications/Mail.app/Contents/MacOS/Mail" }))
        // A command run from a denied app is not that app: only system XPC services borrow their client's identity.
        XCTAssertFalse(d.matches(path: "/usr/bin/curl", responsiblePath: { "/Applications/Safari.app/Contents/MacOS/Safari" }))
    }

    func testBundleRoot() {
        XCTAssertEqual(ProcessGrouping.bundleRoot(of: "/Applications/Google Chrome.app/Contents/Frameworks/F/Helpers/Google Chrome Helper.app/Contents/MacOS/x"), "/Applications/Google Chrome.app")
        XCTAssertEqual(ProcessGrouping.bundleRoot(of: "/Users/me/Library/Application Support/Steam/Steam.AppBundle/Steam/Contents/Frameworks/Steam Helper.app/Contents/MacOS/Steam Helper"),
                       "/Users/me/Library/Application Support/Steam/Steam.AppBundle")
        XCTAssertNil(ProcessGrouping.bundleRoot(of: "/usr/bin/curl"))
    }

    func testRulesAreStatelessPortRulesOnly() {
        let r = PFRules.render(ports: [51000, 50000])
        XCTAssertTrue(r.contains("block return-rst out quick on ! lo0 proto tcp from any port { 50000 51000 } to any no state\n"))
        XCTAssertTrue(r.contains("block return-icmp out quick on ! lo0 proto udp from any port { 50000 51000 } to any no state\n"))
        XCTAssertTrue(r.contains("block drop in quick on ! lo0 proto { tcp udp } from any to any port { 50000 51000 } no state\n"))
        // Nothing about addresses, tables or pass rules: other apps and DNS are never touched.
        for forbidden in ["table", "<", "pass", "to <", "from <"] { XCTAssertFalse(r.contains(forbidden), forbidden) }
        XCTAssertEqual(PFRules.render(ports: []), "")
    }

    func testParsePorts() {
        XCTAssertEqual(PFRules.parsePorts("443\n80\nabc\n0\n70000\n443\n; rm\n"), [80, 443])
    }

    func testDaemonLoadsRulesForItsOwnSocketsAndNothingElse() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("rat-enf-\(UUID())")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        // This test process listens-and-connects over loopback and is "denied"; loopback is public-excluded but its port is still collected.
        let exe = ConnectionSampler.path(of: getpid())
        try (exe + "\n").write(to: dir.appendingPathComponent("denied.txt"), atomically: true, encoding: .utf8)
        let server = socket(AF_INET, SOCK_DGRAM, 0), client = socket(AF_INET, SOCK_DGRAM, 0)
        defer { close(server); close(client) }
        var addr = sockaddr_in(); addr.sin_family = sa_family_t(AF_INET); addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        addr.sin_addr.s_addr = UInt32(0x7f000001).bigEndian
        withUnsafePointer(to: &addr) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { _ = Darwin.bind(client, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) } }
        var bound = sockaddr_in(); var len = socklen_t(MemoryLayout<sockaddr_in>.size)
        withUnsafeMutablePointer(to: &bound) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { _ = getsockname(client, $0, &len) } }
        let port = Int(UInt16(bigEndian: bound.sin_port))

        var calls: [(String, [String], String?)] = []
        var s = EnforcerDaemon.Settings(deniedFile: dir.appendingPathComponent("denied.txt").path, portsFile: dir.appendingPathComponent("ports.txt").path)
        s.anchor = "com.apple/rat-unittest"
        let d = EnforcerDaemon(settings: s, run: { calls.append(($0, $1, $2)); return 0 }, capture: { _, _ in "" })
        XCTAssertTrue(d.tick())
        let rules = calls.compactMap { $0.2 }.last ?? ""
        XCTAssertTrue(rules.contains("\(port)"), rules)
        XCTAssertTrue(calls.allSatisfy { $0.1.contains("com.apple/rat-unittest") }, "only the daemon's own anchor is touched")
        XCTAssertFalse(calls.contains { $0.1.contains("-k") }, "no states are killed: they may belong to other apps")

        // Nothing denied: no ports are ever loaded.
        try "".write(to: dir.appendingPathComponent("denied.txt"), atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.modificationDate: Date().addingTimeInterval(5)], ofItemAtPath: dir.appendingPathComponent("denied.txt").path)
        calls.removeAll()
        let idle = EnforcerDaemon(settings: s, run: { calls.append(($0, $1, $2)); return 0 }, capture: { _, _ in "" })
        XCTAssertFalse(idle.tick())
        XCTAssertFalse(calls.contains { ($0.2 ?? "").contains("port {") })
    }

    func testPortsNamedByRatAreBlockedEvenWithoutDeniedApps() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("rat-enf-\(UUID())")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        try "".write(to: dir.appendingPathComponent("denied.txt"), atomically: true, encoding: .utf8)
        try "61234\n".write(to: dir.appendingPathComponent("ports.txt"), atomically: true, encoding: .utf8)
        var calls: [(String, [String], String?)] = []
        var s = EnforcerDaemon.Settings(deniedFile: dir.appendingPathComponent("denied.txt").path, portsFile: dir.appendingPathComponent("ports.txt").path)
        s.anchor = "com.apple/rat-unittest"
        let d = EnforcerDaemon(settings: s, run: { calls.append(($0, $1, $2)); return 0 }, capture: { _, _ in "" })
        XCTAssertFalse(d.tick())
        XCTAssertTrue((calls.last?.2 ?? "").contains("61234"))
    }

    // MARK: 1.0.5

    /// UDP socket bound to an ephemeral loopback port; returns (fd, port).
    private func boundSocket() -> (Int32, Int) {
        let fd = socket(AF_INET, SOCK_DGRAM, 0)
        var addr = sockaddr_in(); addr.sin_family = sa_family_t(AF_INET); addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        addr.sin_addr.s_addr = UInt32(0x7f000001).bigEndian
        withUnsafePointer(to: &addr) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { _ = Darwin.bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) } }
        var bound = sockaddr_in(); var len = socklen_t(MemoryLayout<sockaddr_in>.size)
        withUnsafeMutablePointer(to: &bound) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { _ = getsockname(fd, $0, &len) } }
        return (fd, Int(UInt16(bigEndian: bound.sin_port)))
    }

    private func daemonForThisProcess(_ dir: URL, status: String? = nil) throws -> (EnforcerDaemon, () -> [String]) {
        try (ConnectionSampler.path(of: getpid()) + "\n").write(to: dir.appendingPathComponent("denied.txt"), atomically: true, encoding: .utf8)
        var s = EnforcerDaemon.Settings(deniedFile: dir.appendingPathComponent("denied.txt").path, statusFile: status)
        s.anchor = "com.apple/rat-unittest"
        var loaded: [String] = []
        let d = EnforcerDaemon(settings: s, run: { _, args, stdin in if args.contains("-f") { loaded.append(stdin ?? "") }; return 0 },
                               capture: { _, args in args == ["-s", "info"] ? "Status: Enabled" : args == ["-s", "rules"] ? "anchor \"com.apple/*\" all" : "" })
        return (d, { loaded })
    }

    /// A descriptor that is closed and reused for a new socket must be read again: the new port is blocked at once.
    func testReusedDescriptorIsReadAgain() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("rat-enf-\(UUID())")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let (d, loaded) = try daemonForThisProcess(dir)
        let (fd1, port1) = boundSocket()
        XCTAssertTrue(d.tick())
        XCTAssertTrue(d.loadedPorts.contains(port1))
        close(fd1)
        let (fd2, port2) = boundSocket()
        defer { close(fd2) }
        XCTAssertEqual(fd2, fd1, "the kernel hands out the lowest free descriptor again")
        XCTAssertNotEqual(port2, port1)
        d.tick()
        XCTAssertTrue(d.loadedPorts.contains(port2), "the new socket on the reused descriptor is blocked on the next pass")
        XCTAssertTrue(loaded().last?.contains("\(port2)") ?? false)
    }

    /// Sockets that existed before the app was denied are blocked on the first pass after the deny.
    func testSocketsOpenedBeforeTheDenyAreBlocked() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("rat-enf-\(UUID())")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let (fd, port) = boundSocket()
        defer { close(fd) }
        try "".write(to: dir.appendingPathComponent("denied.txt"), atomically: true, encoding: .utf8)
        var s = EnforcerDaemon.Settings(deniedFile: dir.appendingPathComponent("denied.txt").path)
        s.anchor = "com.apple/rat-unittest"
        let d = EnforcerDaemon(settings: s, run: { _, _, _ in 0 }, capture: { _, _ in "" })
        XCTAssertFalse(d.tick())
        try (ConnectionSampler.path(of: getpid()) + "\n").write(to: dir.appendingPathComponent("denied.txt"), atomically: true, encoding: .utf8)
        XCTAssertTrue(d.tick(now: Date().addingTimeInterval(0.1)), "the deny list is checked every 50 ms")
        XCTAssertTrue(d.loadedPorts.contains(port))
    }

    func testStatusFileReportsDeniedProcessesAndPorts() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("rat-enf-\(UUID())")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let statusPath = dir.appendingPathComponent("status.json").path
        let (d, _) = try daemonForThisProcess(dir, status: statusPath)
        let (fd, _) = boundSocket()
        defer { close(fd) }
        d.tick()
        let dec = JSONDecoder(); dec.dateDecodingStrategy = .secondsSince1970
        let st = try dec.decode(EnforcerStatus.self, from: Data(contentsOf: URL(fileURLWithPath: statusPath)))
        XCTAssertTrue(st.pfEnabled)
        XCTAssertTrue(st.anchorHooked)
        XCTAssertEqual(st.deniedApps[ConnectionSampler.path(of: getpid())]?.processes, 1)
        XCTAssertGreaterThanOrEqual(st.blockedPorts, 1)
        let perms = try FileManager.default.attributesOfItem(atPath: statusPath)[.posixPermissions] as? Int
        XCTAssertEqual(perms, 0o644)
    }

    func testSymlinkedAppMatchesItsRealPath() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("rat-enf-\(UUID())")
        let real = dir.appendingPathComponent("Real/Safari.app")
        try FileManager.default.createDirectory(at: real, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let link = dir.appendingPathComponent("Safari.app")
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: real)
        let d = DeniedApps(text: link.path + "\n")
        let resolved = String(cString: realpath(real.path, nil))
        XCTAssertTrue(d.matches(path: resolved + "/Contents/MacOS/Safari", responsiblePath: { nil }))
        // On this Mac /Applications/Safari.app is itself a symlink into the Safari cryptex.
        if let target = try? FileManager.default.destinationOfSymbolicLink(atPath: "/Applications/Safari.app"), !target.isEmpty {
            let safari = DeniedApps(text: "/Applications/Safari.app\n")
            let running = String(cString: realpath("/Applications/Safari.app", nil)) + "/Contents/MacOS/Safari"
            XCTAssertTrue(safari.matches(path: running, responsiblePath: { nil }), running)
        }
    }

    func testStateParsingFindsOnlyDeniedLocalPorts() {
        let text = """
        ALL tcp 192.168.1.5:54104 -> 141.95.207.211:443       ESTABLISHED:ESTABLISHED
        ALL udp 192.168.1.5:61000 -> 142.250.1.1:443       MULTIPLE:MULTIPLE
        ALL tcp 192.168.1.5:54999 -> 141.95.207.211:443       ESTABLISHED:ESTABLISHED
        ALL tcp 2a01:db8::5[54105] -> 2a00:1450::1[443]       ESTABLISHED:ESTABLISHED
        No ALTQ support in kernel
        """
        let pairs = PFStates.pairs(in: text, localPorts: [54104, 61000, 54105])
        XCTAssertEqual(pairs.map { "\($0.0) \($0.1)" }, ["192.168.1.5 141.95.207.211", "192.168.1.5 142.250.1.1", "2a01:db8::5 2a00:1450::1"])
        XCTAssertTrue(PFStates.hooksAnchor("scrub-anchor \"com.apple/*\" all fragment reassemble\nanchor \"com.apple/*\" all\n", anchor: "com.apple/rat"))
        XCTAssertFalse(PFStates.hooksAnchor("pass all\n", anchor: "com.apple/rat"))
    }
}
