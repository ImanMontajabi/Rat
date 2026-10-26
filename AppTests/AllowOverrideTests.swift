import XCTest
import RatFilterCore
import RatMonitor
import RatEnforce
@testable import Rat

/// The process list's ✓ allows the whole app past its own narrower deny rules, the mirror of its ✗ winning over
/// narrower allow rules (1.0.5); and Repair Firewall reaches the daemon.
@MainActor
final class AllowOverrideTests: XCTestCase {
    private func tempDir() throws -> URL {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("rat-allow-\(UUID())")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        addTeardownBlock { try? FileManager.default.removeItem(at: dir) }
        return dir
    }

    func testListAllowOverridesTheAppsNarrowDenyRules() async throws {
        let dir = try tempDir()
        // Connections are judged once their reverse lookup has answered (here: no name).
        let names = HostNames(resolve: { _ in nil })
        for a in ["142.250.1.1", "203.0.113.66"] { _ = names.lookup(a) }
        let deadline = Date().addingTimeInterval(5)
        while !["142.250.1.1", "203.0.113.66"].allSatisfy({ names.lookup($0).settled }), Date() < deadline {
            RunLoop.current.run(until: Date().addingTimeInterval(0.02))
        }
        let l = Ledger(directory: dir, helperInstalled: true, names: names)
        let chrome = "/Applications/Google Chrome.app", exe = chrome + "/Contents/MacOS/Google Chrome"
        let p = l.rules.ruleSet.activeProfileID
        l.rules.ruleSet.rules = [
            Rule(verdict: .deny, processPath: chrome, remoteAddress: "142.250.1.1", profileID: p, note: "From a connection alert"),
            Rule(verdict: .deny, remoteAddress: "203.0.113.66", profileID: p),   // any process
        ]
        let conns = [ObservedConnection(pid: 812, processPath: exe, proto: .tcp, remoteAddress: "142.250.1.1", remotePort: 443, localPort: 50200, tcpState: "ESTABLISHED"),
                     ObservedConnection(pid: 812, processPath: exe, proto: .udp, remoteAddress: "203.0.113.66", remotePort: 443, localPort: 50201, tcpState: nil)]
        func verdict(_ address: String) -> Verdict? { l.apps.first { $0.identity.ruleKey == chrome }?.remotes.first { $0.address == address }?.verdict }
        // What the daemon is handed after a pass (the sampling loop calls `refreshEnforcement` after `ingest`).
        func blocked() throws -> String {
            l.refreshEnforcement()
            return try String(contentsOf: dir.appendingPathComponent("denied-ports.txt"), encoding: .utf8)
        }

        await l.ingest(conns, [])
        XCTAssertEqual(verdict("142.250.1.1"), .deny)
        XCTAssertTrue(try blocked().contains("50200"))

        l.setPolicy(.allow, for: chrome)
        XCTAssertEqual(l.rules.policy(for: chrome), .allow)
        await l.ingest(conns, [])
        XCTAssertEqual(verdict("142.250.1.1"), .allow, "the app's own deny rule gives way to the ✓")
        XCTAssertFalse(try blocked().contains("50200"), "and its socket is not blocked")
        XCTAssertEqual(verdict("203.0.113.66"), .deny, "a rule for any process still applies")
        XCTAssertTrue(try blocked().contains("50201"))
        XCTAssertEqual(l.rules.rules(for: chrome).filter { $0.verdict == .deny }.count, 1, "the narrow rule is kept, only overridden")
        XCTAssertFalse(l.deniedAppPaths.contains(chrome))

        l.setPolicy(nil, for: chrome)
        await l.ingest(conns, [])
        XCTAssertEqual(verdict("142.250.1.1"), .deny, "without the ✓ the narrow rule applies again")
    }

    func testRepairFirewallTouchesTheRequestFileTheDaemonWatches() throws {
        let dir = try tempDir()
        let e = Enforcer(supportDirectory: dir, helperInstalled: true, statusPath: dir.appendingPathComponent("status.json").path)
        XCTAssertFalse(FileManager.default.fileExists(atPath: e.repairURL.path))
        e.requestRepair()
        XCTAssertTrue(FileManager.default.fileExists(atPath: e.repairURL.path))
        XCTAssertEqual(e.repairURL.lastPathComponent, "pf-repair-request")
        XCTAssertNil(e.lastError)
    }

    /// Status files of daemons before 1.4.0 have no repair fields; newer ones report them.
    func testStatusDecodesWithAndWithoutRepairFields() throws {
        let dec = JSONDecoder()
        dec.dateDecodingStrategy = .secondsSince1970
        let old = #"{"pid":552,"updated":1793027412,"pfEnabled":false,"anchorHooked":false,"deniedApps":{},"blockedPorts":0}"#
        let s1 = try dec.decode(EnforcerStatus.self, from: Data(old.utf8))
        XCTAssertNil(s1.pfIssue); XCTAssertNil(s1.repairs)
        let new = #"{"pid":552,"updated":1793027412,"pfEnabled":true,"anchorHooked":true,"deniedApps":{},"blockedPorts":0,"repairs":2,"lastRepair":"turned pf on again","lastRepairAt":1793027400}"#
        let s2 = try dec.decode(EnforcerStatus.self, from: Data(new.utf8))
        XCTAssertEqual(s2.repairs, 2); XCTAssertEqual(s2.lastRepair, "turned pf on again")
    }
}
