import XCTest
@testable import RatFilterCore

final class RuleEngineTests: XCTestCase {
    let curl = ProcessIdentity(signingID: "com.apple.curl", teamID: nil, path: "/usr/bin/curl")
    func conn(_ host: String, port: Int = 443) -> Connection {
        Connection(process: curl, host: host, address: "1.2.3.4", port: port)
    }

    func testDefaultAsks() {
        XCTAssertEqual(RuleEngine().evaluate(conn("a.com")), .ask)
    }

    func testDomainMatchesSubdomains() {
        let e = RuleEngine(rules: [Rule(verdict: .deny, remoteDomain: "evil.com")])
        XCTAssertEqual(e.evaluate(conn("x.evil.com")), .deny)
        XCTAssertEqual(e.evaluate(conn("notevil.com")), .ask)
    }

    func testSpecificBeatsGeneral() {
        let e = RuleEngine(rules: [
            Rule(verdict: .deny, signingID: "com.apple.curl"),
            Rule(verdict: .allow, signingID: "com.apple.curl", remoteDomain: "example.com", ports: 443...443),
        ])
        XCTAssertEqual(e.evaluate(conn("example.com")), .allow)
        XCTAssertEqual(e.evaluate(conn("other.com")), .deny)
    }

    func testDenyWinsTie() {
        let e = RuleEngine(rules: [Rule(verdict: .allow, remoteDomain: "a.com"), Rule(verdict: .deny, remoteDomain: "a.com")])
        XCTAssertEqual(e.evaluate(conn("a.com")), .deny)
    }

    func testDisabledIgnoredButUnapprovedStillActive() {
        XCTAssertEqual(RuleEngine(rules: [Rule(verdict: .deny, enabled: false)]).evaluate(conn("a.com")), .ask)
        XCTAssertEqual(RuleEngine(rules: [Rule(verdict: .deny, approved: false)]).evaluate(conn("a.com")), .deny)
    }

    func testStoreRoundTrip() throws {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("rules-\(UUID()).json")
        let store = RuleStore(url: url)
        try store.save([Rule(verdict: .deny, remoteDomain: "a.com", ports: 80...443)])
        XCTAssertEqual(try store.load().first?.ports, 80...443)
    }

    // MARK: v1 rule model

    func testProcessPathMatchesInsideBundle() {
        let e = RuleEngine(rules: [Rule(verdict: .deny, processPath: "/Applications/Foo.app")])
        let inside = Connection(process: ProcessIdentity(path: "/Applications/Foo.app/Contents/MacOS/Foo"), address: "1.1.1.1", port: 443)
        let sibling = Connection(process: ProcessIdentity(path: "/Applications/Foo.app.bak/x"), address: "1.1.1.1", port: 443)
        XCTAssertEqual(e.evaluate(inside), .deny)
        XCTAssertEqual(e.evaluate(sibling), .ask)
    }

    func testExactHostDoesNotMatchSubdomain() {
        let e = RuleEngine(rules: [Rule(verdict: .deny, remoteHost: "a.com")])
        XCTAssertEqual(e.evaluate(conn("a.com")), .deny)
        XCTAssertEqual(e.evaluate(conn("x.a.com")), .ask)
    }

    func testPortRangeAndProtocol() {
        let e = RuleEngine(rules: [Rule(verdict: .allow, ports: 8000...8100, proto: .udp)])
        XCTAssertEqual(e.evaluate(Connection(process: curl, host: "a.com", address: "1.2.3.4", port: 8050, proto: .udp)), .allow)
        XCTAssertEqual(e.evaluate(Connection(process: curl, host: "a.com", address: "1.2.3.4", port: 8050, proto: .tcp)), .ask)
        XCTAssertEqual(e.evaluate(Connection(process: curl, host: "a.com", address: "1.2.3.4", port: 9000, proto: .udp)), .ask)
    }

    func testProfilesScopeRules() {
        var s = RuleSet.standard()
        let work = s.profiles[1]
        s.rules = [Rule(verdict: .deny, remoteDomain: "a.com", profileID: work.id)]
        let e = RuleEngine(ruleSet: s)
        XCTAssertEqual(e.evaluate(conn("a.com")), .ask)               // Home is active
        var t = e.ruleSet; t.activeProfileID = work.id; e.ruleSet = t
        XCTAssertEqual(e.evaluate(conn("a.com")), .deny)
    }

    func testDisabledGroupSilencesItsRules() {
        var s = RuleSet.standard()
        let g = RuleGroup(name: "Ads", enabled: false)
        s.groups = [g]; s.rules = [Rule(verdict: .deny, remoteDomain: "a.com", groupID: g.id)]
        let e = RuleEngine(ruleSet: s)
        XCTAssertEqual(e.evaluate(conn("a.com")), .ask)
        s.groups[0].enabled = true; e.ruleSet = s
        XCTAssertEqual(e.evaluate(conn("a.com")), .deny)
    }

    func testSilentModeChangesDefault() {
        let e = RuleEngine()
        e.defaultVerdict = .allow
        XCTAssertEqual(e.evaluate(conn("x.com")), .allow)
        e.defaultVerdict = .ask
        XCTAssertEqual(e.evaluate(conn("x.com")), .ask)
    }

    func testImportMarksUnapprovedAndSkipsDuplicates() throws {
        let r = Rule(verdict: .deny, remoteDomain: "a.com")
        let e = RuleEngine()
        let data = try RuleExport(groups: [], rules: [r]).encoded()
        XCTAssertEqual(e.importRules(try RuleExport.decode(data), markUnapproved: true), 1)
        XCTAssertEqual(e.importRules(try RuleExport.decode(data), markUnapproved: true), 0)
        XCTAssertFalse(e.allRules[0].approved)
        XCTAssertEqual(e.evaluate(conn("a.com")), .ask)               // imported rules are disabled until approved
        var rules = e.allRules; rules[0].approved = true; rules[0].enabled = true; e.setRules(rules)
        XCTAssertEqual(e.evaluate(conn("a.com")), .deny)
    }

    func testImportAcceptsLegacyBareArray() throws {
        let legacy = #"[{"verdict":"deny","remoteDomain":"old.com"}]"#.data(using: .utf8)!
        let x = try RuleExport.decode(legacy)
        XCTAssertEqual(x.rules.first?.remoteDomain, "old.com")
        XCTAssertEqual(x.rules.first?.lifetime, .forever)
    }

    func testSessionRulesArePurgedAndNotPersisted() throws {
        let e = RuleEngine(rules: [Rule(verdict: .deny, remoteDomain: "a.com", lifetime: .untilQuit), Rule(verdict: .deny, remoteDomain: "b.com")])
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("set-\(UUID()).json")
        try RuleStore(url: url).saveSet(e.ruleSet)
        XCTAssertEqual(try RuleStore(url: url).loadSet().rules.count, 1)
        e.purgeSessionRules()
        XCTAssertEqual(e.allRules.count, 1)
    }

    func testAutomaticProfileSwitchingLookup() {
        var s = RuleSet.standard()
        let t = NetworkTrigger(signature: "CoffeeShop", name: "Cafe", profileID: s.profiles[2].id)
        s.triggers = [t]
        let e = RuleEngine(ruleSet: s)
        XCTAssertEqual(e.profile(forNetwork: "CoffeeShop"), s.profiles[2].id)
        XCTAssertNil(e.profile(forNetwork: "Elsewhere"))
    }

    func testRuleSummary() {
        XCTAssertEqual(Rule(verdict: .allow, processPath: "/Applications/Foo.app", remoteDomain: "a.com", ports: 443...443).summary, "Foo → *.a.com:443")
    }

    func testImportDropsUnknownProfileScope() {
        let e = RuleEngine()
        let foreign = Rule(verdict: .deny, remoteDomain: "a.com", profileID: UUID())
        e.importRules(RuleExport(groups: [], rules: [foreign]), markUnapproved: false)
        XCTAssertNil(e.allRules[0].profileID)
        XCTAssertEqual(e.evaluate(conn("a.com")), .deny)
    }
}
