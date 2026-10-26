import XCTest
@testable import RatEnforce
import RatMonitor

/// pf keeps working when a VPN client turns it off or replaces the main ruleset (Cloudflare WARP does both), and
/// every socket of a denied app is blocked, unconnected UDP (QUIC, WireGuard) and IPv6 included.
final class PFHealTests: XCTestCase {
    private let anchor = "com.apple/rat-unittest"
    private let appleRules = "scrub-anchor \"com.apple/*\" all fragment reassemble\nanchor \"com.apple/*\" all\n"
    private let appleNat = "nat-anchor \"com.apple/*\" all\nrdr-anchor \"com.apple/*\" all\n"
    private let appleConfig = """
    #
    # Default PF configuration file.
    #
    scrub-anchor "com.apple/*"
    nat-anchor "com.apple/*"
    rdr-anchor "com.apple/*"
    dummynet-anchor "com.apple/*"
    anchor "com.apple/*"
    load anchor "com.apple" from "/etc/pf.anchors/com.apple"

    """

    // MARK: the plan

    func testRunningAndHookedNeedsNothing() {
        XCTAssertEqual(PFHeal.plan(enabled: true, rules: appleRules, nat: appleNat, config: appleConfig, anchor: anchor), .none)
        XCTAssertEqual(PFHeal.plan(enabled: true, rules: "No ALTQ support in kernel\nALTQ related functions disabled\n" + appleRules, nat: appleNat, config: appleConfig, anchor: anchor), .none)
    }

    func testTurnedOffWithOnlyApplesAnchorsIsTurnedOn() {
        XCTAssertEqual(PFHeal.plan(enabled: false, rules: appleRules, nat: appleNat, config: appleConfig, anchor: anchor), .enable)
    }

    /// Turning pf on with a disconnected VPN's rules still loaded could bring back its kill switch, so the system
    /// configuration is loaded first.
    func testTurnedOffWithAnotherProgramsRulesLoadsTheSystemConfigFirst() {
        let warp = "anchor \"com.cloudflare.warp_svc\" all\n"
        XCTAssertEqual(PFHeal.plan(enabled: false, rules: warp, nat: "", config: appleConfig, anchor: anchor), .reloadSystemConfig)
        XCTAssertEqual(PFHeal.plan(enabled: false, rules: appleRules + "block drop out all\n", nat: appleNat, config: appleConfig, anchor: anchor), .reloadSystemConfig)
        XCTAssertEqual(PFHeal.plan(enabled: false, rules: "", nat: "", config: appleConfig, anchor: anchor), .reloadSystemConfig, "a flushed main ruleset")
    }

    /// While pf runs another program's anchors, Apple's are put back next to them and theirs stay.
    func testRunningWithoutApplesAnchorsIsRehookedKeepingTheOtherPrograms() {
        let rules = "scrub-anchor \"vpn.scrub\" all fragment reassemble\nanchor \"com.cloudflare.warp_svc\" all\nanchor \"vpn/*\" on utun4 all\n"
        let nat = "nat-anchor \"vpn.nat\" all\n"
        guard case .rehook(let ruleset) = PFHeal.plan(enabled: true, rules: rules, nat: nat, config: appleConfig, anchor: anchor) else {
            return XCTFail("expected a rehook")
        }
        XCTAssertEqual(ruleset, """
        scrub-anchor "com.apple/*"
        scrub-anchor "vpn.scrub" all fragment reassemble
        nat-anchor "com.apple/*"
        rdr-anchor "com.apple/*"
        nat-anchor "vpn.nat" all
        anchor "com.apple/*"
        anchor "com.cloudflare.warp_svc" all
        anchor "vpn/*" on utun4 all

        """)
    }

    /// Rules of its own in the main ruleset (not anchors) are another program's firewall: never replaced while pf
    /// runs them, unless the user asks for the repair.
    func testAnotherProgramsOwnRulesAreLeftAloneUnlessTheUserAsks() {
        let rules = "block drop out quick on en0 all\npass out quick on utun4 all\n"
        guard case .blocked(let why) = PFHeal.plan(enabled: true, rules: rules, nat: "", config: appleConfig, anchor: anchor) else {
            return XCTFail("expected no change")
        }
        XCTAssertTrue(why.contains("Repair Firewall"), why)
        XCTAssertEqual(PFHeal.plan(enabled: true, rules: rules, nat: "", config: appleConfig, anchor: anchor, force: true), .reloadSystemConfig)
    }

    func testAChangedSystemConfigIsNeverEdited() {
        let custom = "# mine\n#anchor \"com.apple/*\"\nblock in all\n"
        XCTAssertFalse(PFHeal.systemConfigHooks(custom))
        XCTAssertTrue(PFHeal.systemConfigHooks(appleConfig))
        guard case .blocked(let why) = PFHeal.plan(enabled: false, rules: "", nat: "", config: custom, anchor: anchor) else { return XCTFail() }
        XCTAssertTrue(why.contains("/etc/pf.conf"), why)
        guard case .blocked = PFHeal.plan(enabled: true, rules: "block in all\n", nat: "", config: custom, anchor: anchor, force: true) else { return XCTFail() }
    }

    // MARK: the daemon against a pf that another program changes

    /// pf as `pfctl` sees it: on or off, and the main ruleset.
    private final class FakePF {
        var enabled: Bool
        var rules: String
        var nat: String
        var configLoads = 0
        var anchorLoads: [String] = []
        var commands: [[String]] = []
        init(enabled: Bool, rules: String, nat: String) { self.enabled = enabled; self.rules = rules; self.nat = nat }

        func capture(_ exe: String, _ args: [String]) -> String {
            commands.append(args)
            switch args {
            case ["-s", "info"]: return enabled ? "Status: Enabled for 0 days 00:01:02           Debug: Urgent\n" : "Status: Disabled                              Debug: Urgent\n"
            case ["-s", "rules"]: return rules
            case ["-s", "nat"]: return nat
            case ["-E"]: enabled = true; return "No ALTQ support in kernel\npf enabled\nToken : 1234\n"
            default: return ""
            }
        }

        func run(_ exe: String, _ args: [String], _ stdin: String?) -> Int32 {
            commands.append(args)
            if args.first == "-a" { if args.contains("-f") { anchorLoads.append(stdin ?? "") }; return 0 }
            if args.first == "-n" { return 0 }
            if args == ["-N", "-R", "-f", "-"], let text = stdin {
                let lines = text.split(separator: "\n").map(String.init)
                rules = lines.filter { $0.hasPrefix("scrub-anchor") || $0.hasPrefix("anchor") }.map { $0 + " all" }.joined(separator: "\n")
                nat = lines.filter { $0.hasPrefix("nat-anchor") || $0.hasPrefix("rdr-anchor") }.map { $0 + " all" }.joined(separator: "\n")
                return 0
            }
            if args.first == "-f" {
                configLoads += 1
                rules = "scrub-anchor \"com.apple/*\" all fragment reassemble\nanchor \"com.apple/*\" all\n"
                nat = "nat-anchor \"com.apple/*\" all\nrdr-anchor \"com.apple/*\" all\n"
            }
            return 0
        }
    }

    private func daemon(_ pf: FakePF, dir: URL) throws -> (EnforcerDaemon, EnforcerDaemon.Settings) {
        try "".write(to: dir.appendingPathComponent("denied.txt"), atomically: true, encoding: .utf8)
        try appleConfig.write(to: dir.appendingPathComponent("pf.conf"), atomically: true, encoding: .utf8)
        var s = EnforcerDaemon.Settings(deniedFile: dir.appendingPathComponent("denied.txt").path, statusFile: dir.appendingPathComponent("status.json").path)
        s.anchor = anchor
        s.systemConfig = dir.appendingPathComponent("pf.conf").path
        s.repairFile = dir.appendingPathComponent("repair").path
        return (EnforcerDaemon(settings: s, run: pf.run, capture: pf.capture), s)
    }

    private func tempDir() throws -> URL {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("rat-heal-\(UUID())")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        addTeardownBlock { try? FileManager.default.removeItem(at: dir) }
        return dir
    }

    private func status(_ dir: URL) throws -> EnforcerStatus {
        let dec = JSONDecoder()
        dec.dateDecodingStrategy = .secondsSince1970
        return try dec.decode(EnforcerStatus.self, from: Data(contentsOf: dir.appendingPathComponent("status.json")))
    }

    /// What happened on this Mac: WARP replaced the main ruleset with its own anchor and stopped pf. Within one
    /// watchdog pass pf runs again with Apple's anchors, and Rat's anchor is loaded again.
    func testDaemonRecoversFromAVPNThatStoppedPFAndReplacedItsRuleset() throws {
        let dir = try tempDir()
        let pf = FakePF(enabled: true, rules: appleRules, nat: appleNat)
        let (d, _) = try daemon(pf, dir: dir)
        d.start()
        XCTAssertTrue(pf.commands.contains(["-E"]), "a reference keeps pf on while the daemon runs")
        let t0 = Date()
        d.tick(now: t0)
        XCTAssertEqual(try status(dir).pfEnabled, true)
        XCTAssertEqual(try status(dir).anchorHooked, true)

        // The VPN client disconnects.
        pf.rules = "anchor \"com.cloudflare.warp_svc\" all\n"; pf.nat = ""; pf.enabled = false
        let loadsBefore = pf.anchorLoads.count
        d.tick(now: t0.addingTimeInterval(2.1))
        XCTAssertTrue(pf.enabled, "turned on again")
        XCTAssertEqual(pf.configLoads, 1, "with /etc/pf.conf loaded first, so no stale rule of the VPN's comes back")
        XCTAssertTrue(PFStates.hooksAnchor(pf.rules, anchor: anchor))
        XCTAssertGreaterThan(pf.anchorLoads.count + pf.commands.filter { $0 == ["-a", anchor, "-F", "all"] }.count, loadsBefore, "Rat's anchor is loaded again")
        d.tick(now: t0.addingTimeInterval(3.2))
        let st = try status(dir)
        XCTAssertTrue(st.pfEnabled); XCTAssertTrue(st.anchorHooked); XCTAssertNil(st.pfIssue)
        XCTAssertEqual(st.repairs, 1)
        XCTAssertEqual(st.lastRepair, "loaded \(dir.appendingPathComponent("pf.conf").path) and turned pf on")
    }

    /// The VPN connects and writes the main ruleset while pf runs: Apple's anchors come back, the VPN's stay.
    func testDaemonRehooksWhileAVPNRunsItsAnchor() throws {
        let dir = try tempDir()
        let pf = FakePF(enabled: true, rules: "anchor \"com.cloudflare.warp_svc\" all\n", nat: "")
        let (d, _) = try daemon(pf, dir: dir)
        d.start()
        XCTAssertEqual(pf.configLoads, 0, "the running VPN's rules are not replaced")
        XCTAssertTrue(pf.commands.contains(["-n", "-N", "-R", "-f", "-"]), "the new ruleset is parsed before it is loaded")
        XCTAssertTrue(PFStates.hooksAnchor(pf.rules, anchor: anchor))
        XCTAssertTrue(pf.rules.contains("anchor \"com.cloudflare.warp_svc\""), pf.rules)
        XCTAssertFalse(pf.commands.contains { $0.contains("-d") }, "pf is never turned off")
    }

    /// A firewall with rules of its own is reported, not replaced; Repair Firewall (the request file) replaces it.
    func testRepairRequestReplacesAnotherProgramsRules() throws {
        let dir = try tempDir()
        let pf = FakePF(enabled: true, rules: "block drop out quick on en0 all\n", nat: "")
        let (d, s) = try daemon(pf, dir: dir)
        d.start()
        let t0 = Date()
        d.tick(now: t0)
        XCTAssertEqual(pf.configLoads, 0)
        let st = try status(dir)
        XCTAssertFalse(st.anchorHooked)
        XCTAssertTrue(st.pfIssue?.contains("Repair Firewall") ?? false, st.pfIssue ?? "nil")

        FileManager.default.createFile(atPath: s.repairFile!, contents: Data())
        d.tick(now: t0.addingTimeInterval(1))
        XCTAssertEqual(pf.configLoads, 1)
        d.tick(now: t0.addingTimeInterval(2))
        XCTAssertNil(try status(dir).pfIssue)
        XCTAssertTrue(try status(dir).anchorHooked)
        d.tick(now: t0.addingTimeInterval(4.5))
        XCTAssertEqual(pf.configLoads, 1, "one request, one repair")
    }

    /// A program that keeps stopping pf is not fought every 2 s.
    func testRepairsBackOffWhenAnotherProgramKeepsUndoingThem() throws {
        let dir = try tempDir()
        let pf = FakePF(enabled: false, rules: appleRules, nat: appleNat)
        let (d, _) = try daemon(pf, dir: dir)
        d.start()
        let t0 = Date()
        var enables = 0
        for i in 1...20 {
            pf.enabled = false
            let before = pf.commands.filter { $0 == ["-E"] }.count
            d.tick(now: t0.addingTimeInterval(Double(i) * 2.1))
            enables += pf.commands.filter { $0 == ["-E"] }.count - before
        }
        XCTAssertLessThan(enables, 12, "about five in the first minute, then one every 30 s")
        XCTAssertTrue(try status(dir).pfIssue?.contains("keeps turning pf off") ?? false)
    }

    // MARK: every socket of a denied app

    private func socket(_ family: Int32, any: Bool) -> (Int32, Int) {
        let fd = Darwin.socket(family, SOCK_DGRAM, 0)
        if family == AF_INET6 {
            var a = sockaddr_in6(); a.sin6_family = sa_family_t(AF_INET6); a.sin6_len = UInt8(MemoryLayout<sockaddr_in6>.size)
            if !any { a.sin6_addr = in6addr_loopback }
            withUnsafePointer(to: &a) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { _ = Darwin.bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in6>.size)) } }
            var b = sockaddr_in6(); var len = socklen_t(MemoryLayout<sockaddr_in6>.size)
            withUnsafeMutablePointer(to: &b) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { _ = getsockname(fd, $0, &len) } }
            return (fd, Int(UInt16(bigEndian: b.sin6_port)))
        }
        var a = sockaddr_in(); a.sin_family = sa_family_t(AF_INET); a.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        a.sin_addr.s_addr = any ? 0 : UInt32(0x7f000001).bigEndian
        withUnsafePointer(to: &a) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { _ = Darwin.bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) } }
        var b = sockaddr_in(); var len = socklen_t(MemoryLayout<sockaddr_in>.size)
        withUnsafeMutablePointer(to: &b) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { _ = getsockname(fd, $0, &len) } }
        return (fd, Int(UInt16(bigEndian: b.sin_port)))
    }

    /// Unconnected UDP (QUIC, WireGuard, WARP, games: `sendto` on a bound socket with no peer) on 0.0.0.0 and on
    /// `::` is blocked like any other socket.
    func testUnconnectedUDPSocketsOfADeniedAppAreBlocked() throws {
        let dir = try tempDir()
        try (ConnectionSampler.path(of: getpid()) + "\n").write(to: dir.appendingPathComponent("denied.txt"), atomically: true, encoding: .utf8)
        var s = EnforcerDaemon.Settings(deniedFile: dir.appendingPathComponent("denied.txt").path)
        s.anchor = anchor
        var loaded = ""
        let d = EnforcerDaemon(settings: s, run: { _, args, stdin in if args.contains("-f") { loaded = stdin ?? "" }; return 0 }, capture: { _, _ in "" })
        let (v4, p4) = socket(AF_INET, any: true), (v6, p6) = socket(AF_INET6, any: true)
        defer { close(v4); close(v6) }
        for fd in [v4, v6] {
            let c = try XCTUnwrap(ConnectionSampler.socketFDs(of: getpid()).contains(fd) ? ConnectionSampler.connection(pid: getpid(), fd: fd, processPath: "") : nil)
            XCTAssertEqual(c.proto, .udp); XCTAssertEqual(c.remotePort, 0, "no peer"); XCTAssertEqual(c.remoteAddress, "")
        }
        XCTAssertTrue(d.tick())
        XCTAssertTrue(d.loadedPorts.contains(p4), "IPv4 wildcard")
        XCTAssertTrue(d.loadedPorts.contains(p6), "IPv6 wildcard")
        XCTAssertTrue(loaded.contains("proto udp from any port {"), loaded)
    }

    /// The rules name no interface but lo0 and no address family: Wi-Fi, Ethernet and every VPN tunnel (`utun*`),
    /// IPv4 and IPv6 alike.
    func testRulesCoverEveryInterfaceAndBothAddressFamilies() {
        let r = PFRules.render(ports: [55996])
        for line in r.split(separator: "\n") {
            XCTAssertTrue(line.contains(" on ! lo0 "), String(line))
            for narrowing in ["inet", " on en", " on utun", "inet6"] { XCTAssertFalse(line.contains(narrowing), "\(line) has \(narrowing)") }
        }
        XCTAssertTrue(r.contains("block return-rst out quick on ! lo0 proto tcp"))
        XCTAssertTrue(r.contains("block return-icmp out quick on ! lo0 proto udp"))
        XCTAssertTrue(r.contains("block drop in quick on ! lo0 proto { tcp udp }"))
    }

    /// Denying Cloudflare WARP covers its root daemon, which lives inside the app.
    func testDenyingAVPNAppCoversItsRootDaemon() {
        let d = DeniedApps(text: "/Applications/Cloudflare WARP.app\n")
        XCTAssertTrue(d.matches(path: "/Applications/Cloudflare WARP.app/Contents/Resources/CloudflareWARP", responsiblePath: { nil }))
        XCTAssertTrue(d.matches(path: "/Applications/Cloudflare WARP.app/Contents/Resources/warp-svc", responsiblePath: { nil }))
        XCTAssertTrue(d.matches(path: "/Applications/Cloudflare WARP.app/Contents/MacOS/Cloudflare WARP", responsiblePath: { nil }))
        XCTAssertFalse(d.matches(path: "/Applications/Warp.app/Contents/MacOS/stable", responsiblePath: { nil }), "the Warp terminal is another app")
    }
}
