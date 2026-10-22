import XCTest
import RatFilterCore
@testable import Rat

@MainActor
final class RulesModelTests: XCTestCase {
    private func model() -> RulesModel {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("rat-test-\(UUID())")
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let m = RulesModel(directory: dir)
        m.silentMode = .off   // these tests exercise alert mode; new installs default to Silent Allow
        return m
    }

    private func alert(host: String = "cdn.example.com", port: Int = 443) -> ConnectionAlert {
        ConnectionAlert(appID: "/Applications/Foo.app", appName: "Foo", host: host, address: "203.0.113.9", port: port, proto: "TCP")
    }

    private func conn(host: String? = "cdn.example.com", port: Int = 443) -> Connection {
        Connection(process: ProcessIdentity(path: "/Applications/Foo.app/Contents/MacOS/Foo"), host: host, address: "203.0.113.9", port: port)
    }

    func testPolicyButtonsCreateAndRemoveWholeAppRule() {
        let m = model()
        XCTAssertNil(m.policy(for: "/Applications/Foo.app"))
        m.setPolicy(.deny, for: "/Applications/Foo.app")
        XCTAssertEqual(m.policy(for: "/Applications/Foo.app"), .deny)
        XCTAssertEqual(m.engine.evaluate(conn()), .deny)
        m.setPolicy(.allow, for: "/Applications/Foo.app")
        XCTAssertEqual(m.ruleSet.rules.count, 1)
        XCTAssertEqual(m.engine.evaluate(conn()), .allow)
        m.setPolicy(nil, for: "/Applications/Foo.app")
        XCTAssertTrue(m.ruleSet.rules.isEmpty)
    }

    func testAlertScopes() {
        let cases: [(RulesModel.Scope, (Rule) -> Bool)] = [
            (.any, { $0.remoteDomain == nil && $0.remoteHost == nil && $0.ports == nil }),
            (.domain, { $0.remoteDomain == "example.com" }),
            (.host, { $0.remoteHost == "cdn.example.com" }),
            (.port, { $0.ports == 443...443 && $0.proto == .tcp }),
        ]
        for (scope, check) in cases {
            let m = model()
            m.addRule(from: alert(), verdict: .allow, scope: scope, lifetime: .forever)
            XCTAssertEqual(m.ruleSet.rules.count, 1, scope.rawValue)
            XCTAssertTrue(check(m.ruleSet.rules[0]), scope.rawValue)
            XCTAssertEqual(m.engine.evaluate(conn()), .allow, scope.rawValue)
        }
    }

    func testIPOnlyHostScopesToAddress() {
        let m = model()
        m.addRule(from: alert(host: "203.0.113.9"), verdict: .deny, scope: .host, lifetime: .forever)
        XCTAssertEqual(m.ruleSet.rules[0].remoteAddress, "203.0.113.9")
    }

    func testLifetimes() {
        let m = model()
        m.addRule(from: alert(), verdict: .allow, scope: .any, lifetime: .once)
        XCTAssertTrue(m.ruleSet.rules.isEmpty, "allow-once stores nothing")
        m.addRule(from: alert(), verdict: .deny, scope: .domain, lifetime: .once)
        XCTAssertEqual(m.ruleSet.rules[0].lifetime, .untilQuit, "deny-once is a session rule pinned to the address")
        XCTAssertEqual(m.ruleSet.rules[0].remoteAddress, "203.0.113.9")
        m.addRule(from: alert(), verdict: .allow, scope: .any, lifetime: .untilQuit)
        m.addRule(from: alert(), verdict: .allow, scope: .port, lifetime: .forever)
        m.purgeSessionRules()
        XCTAssertEqual(m.ruleSet.rules.count, 1)
        XCTAssertEqual(m.ruleSet.rules[0].lifetime, .forever)
    }

    func testMarkNewRulesAsUnapprovedStaysActiveUntilApproved() {
        let m = model()
        m.ruleSet.markNewRulesAsUnapproved = true
        m.addRule(from: alert(), verdict: .deny, scope: .any, lifetime: .forever)
        XCTAssertEqual(m.unapprovedCount, 1)
        XCTAssertEqual(m.engine.evaluate(conn()), .deny)
        m.approveAll()
        XCTAssertEqual(m.unapprovedCount, 0)
    }

    func testRejectRemovesRule() {
        let m = model()
        m.ruleSet.markNewRulesAsUnapproved = true
        m.addRule(from: alert(), verdict: .deny, scope: .any, lifetime: .forever)
        m.rejectAllUnapproved()
        XCTAssertTrue(m.ruleSet.rules.isEmpty)
        XCTAssertEqual(m.engine.evaluate(conn()), .ask)
    }

    func testExportImportRoundTripArrivesDisabledAndUnapproved() throws {
        let a = model(), b = model()
        a.addRule(from: alert(), verdict: .deny, scope: .domain, lifetime: .forever)
        let file = FileManager.default.temporaryDirectory.appendingPathComponent("export-\(UUID()).json")
        a.exportRules(to: file)
        b.importRules(from: file)
        XCTAssertEqual(b.ruleSet.rules.count, 1)
        XCTAssertFalse(b.ruleSet.rules[0].approved)
        XCTAssertFalse(b.ruleSet.rules[0].enabled)
        XCTAssertEqual(b.engine.evaluate(conn()), .ask)
        b.approve(b.ruleSet.rules[0].id)
        XCTAssertEqual(b.engine.evaluate(conn()), .deny)
        b.importRules(from: file)
        XCTAssertEqual(b.ruleSet.rules.count, 1, "re-import is idempotent")
    }

    func testImportOfGarbageReportsFailure() {
        let m = model()
        let file = FileManager.default.temporaryDirectory.appendingPathComponent("bad-\(UUID()).json")
        try? "not json".write(to: file, atomically: true, encoding: .utf8)
        m.importRules(from: file)
        XCTAssertTrue(m.lastMessage?.hasPrefix("Import failed") == true)
    }

    func testProfileSwitchingAndRemoval() {
        let m = model()
        let work = m.ruleSet.profiles[1]
        m.activate(work.id)
        XCTAssertEqual(m.activeProfile?.id, work.id)
        m.removeProfile(work.id)
        XCTAssertNotEqual(m.activeProfile?.id, work.id)
        XCTAssertEqual(m.ruleSet.profiles.count, 2)
    }

    func testAutomaticProfileSwitchingOnKnownNetwork() {
        let m = model()
        let cafe = NetworkWatcher.Network(signature: "CafeWiFi", name: "CafeWiFi")
        let publicProfile = m.ruleSet.profiles[2]
        m.applyNetwork(cafe)
        m.rememberCurrentNetwork(profile: publicProfile.id)
        m.applyNetwork(nil)
        m.ruleSet.automaticProfileSwitching = true
        m.applyNetwork(cafe)
        XCTAssertEqual(m.activeProfile?.id, publicProfile.id)
    }

    func testAutomaticSwitchingOffLeavesProfileAlone() {
        let m = model()
        let cafe = NetworkWatcher.Network(signature: "CafeWiFi", name: "CafeWiFi")
        m.applyNetwork(cafe)
        m.rememberCurrentNetwork(profile: m.ruleSet.profiles[2].id)
        m.applyNetwork(nil)
        m.applyNetwork(cafe)
        XCTAssertEqual(m.activeProfile?.id, m.ruleSet.profiles[0].id)
    }

    func testSilentModeRoundTrip() {
        let m = model()
        for mode in SilentMode.allCases { m.silentMode = mode; XCTAssertEqual(m.silentMode, mode) }
        m.silentMode = .allow
        XCTAssertEqual(m.engine.evaluate(conn()), .allow)
        m.silentMode = .deny
        XCTAssertEqual(m.engine.evaluate(conn()), .deny)
    }

    func testRulesPersistAcrossInstances() {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("rat-persist-\(UUID())")
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let a = RulesModel(directory: dir)
        a.setPolicy(.deny, for: "/Applications/Foo.app")
        a.addRule(from: alert(), verdict: .allow, scope: .any, lifetime: .untilQuit)
        a.saveNow()
        let b = RulesModel(directory: dir)
        XCTAssertEqual(b.ruleSet.rules.count, 1, "session rules are not persisted")
        XCTAssertEqual(b.policy(for: "/Applications/Foo.app"), .deny)
    }

    func testRuleEditorGranularityViaUpsert() {
        let m = model()
        var r = Rule(verdict: .deny, teamID: "ABCDE12345", remoteDomain: "tracker.net", ports: 80...443, proto: .tcp)
        m.upsert(r)
        r.verdict = .allow
        m.upsert(r)
        XCTAssertEqual(m.ruleSet.rules.count, 1)
        XCTAssertEqual(m.ruleSet.rules[0].verdict, .allow)
        XCTAssertEqual(m.ruleSet.rules[0].summary, "Team ABCDE12345 → *.tracker.net:80-443 (TCP)")
    }
}
