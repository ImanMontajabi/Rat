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

    func testRulesBlockPortsBothWaysAndSpareLoopback() {
        let r = PFRules.render(ports: [51000, 50000], addresses: ["203.0.113.5", "2001:db8::1"])
        XCTAssertTrue(r.contains("table <rat_blocked> persist {2001:db8::1 203.0.113.5}"))
        XCTAssertTrue(r.contains("block return-rst out quick on ! lo0 proto tcp from any port { 50000 51000 } to any\n"))
        XCTAssertTrue(r.contains("block return-icmp out quick on ! lo0 proto udp from any port { 50000 51000 } to any\n"))
        XCTAssertTrue(r.contains("block drop in quick on ! lo0 proto { tcp udp } from any to any port { 50000 51000 }\n"))
        XCTAssertFalse(PFRules.render(ports: [], addresses: []).contains("port"))
    }

    func testBlocklistAndPublicAddresses() {
        XCTAssertEqual(PFRules.parseBlocklist("1.1.1.1\nnot-an-ip\n1.1.1.1\n2606:4700::1111\n; rm -rf /\n"), ["1.1.1.1", "2606:4700::1111"])
        for a in ["8.8.8.8", "2606:4700::1111"] { XCTAssertTrue(Address.isPublic(a), a) }
        for a in ["127.0.0.1", "10.1.2.3", "192.168.1.1", "172.16.0.1", "169.254.1.1", "100.64.0.1", "224.0.0.251", "::1", "fe80::1", "fd00::1", "ff02::fb", "::"] {
            XCTAssertFalse(Address.isPublic(a), a)
        }
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
        var s = EnforcerDaemon.Settings(deniedFile: dir.appendingPathComponent("denied.txt").path, blocklistFile: dir.appendingPathComponent("none.txt").path)
        s.anchor = "com.apple/rat-unittest"
        let d = EnforcerDaemon(settings: s, run: { calls.append(($0, $1, $2)); return 0 })
        XCTAssertTrue(d.tick())
        let rules = calls.compactMap { $0.2 }.last ?? ""
        XCTAssertTrue(rules.contains("\(port)"), rules)
        XCTAssertTrue(calls.allSatisfy { $0.1.contains("com.apple/rat-unittest") || $0.1.first == "-k" })

        // Nothing denied: no ports are ever loaded.
        try "".write(to: dir.appendingPathComponent("denied.txt"), atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.modificationDate: Date().addingTimeInterval(5)], ofItemAtPath: dir.appendingPathComponent("denied.txt").path)
        calls.removeAll()
        let idle = EnforcerDaemon(settings: s, run: { calls.append(($0, $1, $2)); return 0 })
        XCTAssertFalse(idle.tick())
        XCTAssertFalse(calls.contains { ($0.2 ?? "").contains("port") })
    }
}
