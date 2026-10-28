import XCTest
@testable import RatFilterCore

/// Rules for one process of an app and for one connection, and which ✗/✓ of the process list decides.
final class RuleScopeTests: XCTestCase {
    let app = "/Applications/Foo.app"
    let main = "/Applications/Foo.app/Contents/MacOS/Foo"
    let updater = "/Applications/Foo.app/Contents/Library/LoginItems/Foo Updater.app/Contents/MacOS/Foo Updater"
    let updaterBundle = "/Applications/Foo.app/Contents/Library/LoginItems/Foo Updater.app"
    /// A system service working for the app (Safari's WebKit networking process).
    let webkit = "/System/Library/Frameworks/WebKit.framework/Versions/A/XPCServices/com.apple.WebKit.Networking.xpc/Contents/MacOS/com.apple.WebKit.Networking"

    func conn(_ exe: String, host: String? = "api.example.com", address: String = "203.0.113.5", port: Int = 443, proto: Connection.Proto = .tcp) -> Connection {
        Connection(process: ProcessIdentity(path: app), executable: exe, host: host, address: address, port: port, proto: proto)
    }

    func rule(_ v: Verdict, _ level: ListLevel? = nil, executable: String? = nil, host: String? = nil, address: String? = nil,
              domain: String? = nil, port: Int? = nil, proto: Connection.Proto? = nil, anyProcess: Bool = false) -> Rule {
        Rule(verdict: v, processPath: anyProcess ? nil : app, executable: executable, listLevel: level, remoteDomain: domain, remoteHost: host,
             remoteAddress: address, ports: port.map { $0...$0 }, proto: proto)
    }

    // MARK: matching

    func testAProcessRuleMatchesOnlyThatProcess() {
        let r = rule(.deny, .process, executable: updater)
        XCTAssertTrue(r.matches(conn(updater)))
        XCTAssertFalse(r.matches(conn(main)))
        XCTAssertFalse(r.matches(Connection(process: ProcessIdentity(path: app), address: "203.0.113.5", port: 443)), "no executable: the app's main process")
        XCTAssertTrue(rule(.deny, .process, executable: updaterBundle).matches(conn(updater)), "a helper's bundle covers its executable")
        XCTAssertFalse(Rule(verdict: .deny, processPath: "/Applications/Other.app", executable: updater).matches(conn(updater)), "and only in its own app")
    }

    /// The `macOS` row's services, and a helper, can be named by their own path: the rule matches the process
    /// that holds the socket. Before 1.5.0 only the app's path was compared, so such rules never matched.
    func testAPathRuleMatchesTheProcessHoldingTheSocket() {
        let mdns = Rule(verdict: .deny, processPath: "/usr/sbin/mDNSResponder")
        let system = Connection(process: ProcessIdentity(path: "macOS"), executable: "/usr/sbin/mDNSResponder", address: "203.0.113.5", port: 53, proto: .udp)
        XCTAssertTrue(mdns.matches(system))
        XCTAssertFalse(mdns.matches(Connection(process: ProcessIdentity(path: "macOS"), executable: "/usr/libexec/trustd", address: "203.0.113.5", port: 443)))
        XCTAssertTrue(Rule(verdict: .deny, processPath: updaterBundle).matches(conn(updater)))
        XCTAssertTrue(Rule(verdict: .allow, processPath: app).matches(conn(webkit)), "the app's rules cover a service working for it")
    }

    func testSpecificity() {
        XCTAssertGreaterThan(rule(.deny, executable: updater).specificity, rule(.deny).specificity)
        XCTAssertGreaterThan(rule(.deny, executable: updater, address: "203.0.113.5", port: 443, proto: .tcp).specificity,
                             rule(.deny, executable: updater).specificity)
    }

    // MARK: which ✗/✓ decides

    private func decide(_ rules: [Rule], _ c: Connection, silent: Verdict = .allow) -> Verdict {
        RuleEngine(rules: rules, defaultVerdict: silent).decide(c).verdict
    }

    func testAProcessAllowIsAnExceptionToTheAppsDeny() {
        let rules = [rule(.deny, .app), rule(.allow, .process, executable: updater)]
        XCTAssertEqual(decide(rules, conn(updater)), .allow)
        XCTAssertEqual(decide(rules, conn(main)), .deny)
    }

    func testAProcessDenyUnderAnAllowedApp() {
        let rules = [rule(.allow, .app), rule(.deny, .process, executable: updater)]
        XCTAssertEqual(decide(rules, conn(updater)), .deny)
        XCTAssertEqual(decide(rules, conn(main)), .allow)
    }

    func testAConnectionDecidesOverItsProcessAndApp() {
        let rules = [rule(.allow, .app), rule(.allow, .process, executable: main),
                     rule(.deny, .connection, executable: main, address: "2001:4860:4828:400::", port: 443, proto: .udp)]
        XCTAssertEqual(decide(rules, conn(main, host: nil, address: "2001:4860:4828:400::", port: 443, proto: .udp)), .deny)
        XCTAssertEqual(decide(rules, conn(main, host: nil, address: "2001:4860:4828:400::", port: 443, proto: .tcp)), .allow, "another protocol")
        XCTAssertEqual(decide(rules, conn(main, host: nil, address: "2a04:4e42:4c::347", port: 443, proto: .udp)), .allow, "another server")
        XCTAssertEqual(decide(rules, conn(updater, host: nil, address: "2001:4860:4828:400::", port: 443, proto: .udp)), .allow, "another process")
        let allowOne = [rule(.deny, .app), rule(.allow, .connection, executable: main, host: "api.example.com", port: 443, proto: .tcp)]
        XCTAssertEqual(decide(allowOne, conn(main)), .allow, "one connection allowed under a denied app")
        XCTAssertEqual(decide(allowOne, conn(main, host: "ads.example.com")), .deny)
    }

    /// Alerts made narrow rules one domain or address at a time; a ✗/✓ in the list wins over them (1.0.5), at
    /// every level.
    func testListButtonsWinOverTheAppsRulesFromAlerts() {
        let fromAlert = rule(.allow, domain: "example.com")
        XCTAssertEqual(decide([rule(.deny, .app), fromAlert], conn(main)), .deny)
        XCTAssertEqual(decide([rule(.deny, .process, executable: main), fromAlert], conn(main)), .deny)
        XCTAssertEqual(decide([rule(.allow, .app), rule(.deny, address: "203.0.113.5")], conn(main)), .allow)
        XCTAssertEqual(decide([fromAlert], conn(main), silent: .deny), .allow, "without a ✗/✓ the most specific rule decides")
    }

    func testAnAllowDoesNotLiftADenyForAnyProcess() {
        let anyDeny = rule(.deny, domain: "tracker.example", anyProcess: true)
        let rules = [rule(.allow, .process, executable: main), anyDeny]
        let d = RuleEngine(rules: rules).decide(conn(main, host: "x.tracker.example"))
        XCTAssertEqual(d.verdict, .deny)
        XCTAssertEqual(d.rule?.id, anyDeny.id)
        XCTAssertEqual(decide(rules, conn(main)), .allow)
        XCTAssertEqual(decide([rule(.allow, .app), anyDeny, rule(.allow, host: "x.tracker.example", anyProcess: true)], conn(main, host: "x.tracker.example")), .allow,
                       "a more specific allow for any process lifts it")
    }

    /// A whole-app rule written in the Rules window counts as the app's ✗/✓, as `RulesModel.policy` shows it.
    func testAWholeAppRuleWithoutALevelIsTheAppsButton() {
        let handWritten = Rule(verdict: .deny, processPath: app)
        XCTAssertEqual(handWritten.effectiveListLevel, .app)
        XCTAssertNil(rule(.deny, domain: "example.com").effectiveListLevel)
        XCTAssertEqual(decide([handWritten, rule(.allow, domain: "example.com")], conn(main)), .deny)
    }

    func testDecisionWithoutRulesIsSilentModeOrAsk() {
        XCTAssertEqual(RuleEngine(rules: [], defaultVerdict: .ask).decide(conn(main)), .init(verdict: .ask, rule: nil))
        XCTAssertEqual(RuleEngine(rules: [], defaultVerdict: .deny).decide(conn(main)).verdict, .deny)
    }

    func testRulesOfAnotherProfileOrDisabledDoNotDecide() {
        var off = rule(.deny, .process, executable: main); off.enabled = false
        XCTAssertEqual(decide([off], conn(main)), .allow)
        var elsewhere = rule(.deny, .process, executable: main); elsewhere.profileID = UUID()
        XCTAssertEqual(decide([elsewhere], conn(main)), .allow)
    }

    // MARK: storage

    func testNewFieldsAreStoredAndOldFilesStillLoad() throws {
        var r = rule(.deny, .connection, executable: updater, address: "203.0.113.5", port: 443, proto: .udp)
        r.createdAt = Date(timeIntervalSince1970: 1_793_000_000)   // the rule file stores whole seconds
        let enc = JSONEncoder(); enc.dateEncodingStrategy = .iso8601
        let dec = JSONDecoder(); dec.dateDecodingStrategy = .iso8601
        let back = try dec.decode(Rule.self, from: enc.encode(r))
        XCTAssertEqual(back, r)
        let old = try dec.decode(Rule.self, from: Data(#"{"verdict":"deny","processPath":"/Applications/Foo.app"}"#.utf8))
        XCTAssertNil(old.executable); XCTAssertNil(old.listLevel)
        let future = try dec.decode(Rule.self, from: Data(#"{"verdict":"deny","processPath":"/Applications/Foo.app","listLevel":"socket"}"#.utf8))
        XCTAssertNil(future.listLevel, "a level from a newer version is ignored, not a failed rule file")
    }

    func testSummaryNamesTheProcess() {
        XCTAssertEqual(rule(.deny, .process, executable: updater).summary, "Foo › Foo Updater → any server")
        XCTAssertEqual(rule(.deny, .connection, executable: main, address: "203.0.113.5", port: 443, proto: .udp).summary, "Foo › Foo → 203.0.113.5:443 (UDP)")
    }
}
