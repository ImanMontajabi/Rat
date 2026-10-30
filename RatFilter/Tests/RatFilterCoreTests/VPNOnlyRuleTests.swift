import XCTest
@testable import RatFilterCore

/// "Only through a VPN" (`Rule.requireVPN`, #45): a deny for the connections that leave outside a VPN tunnel, which
/// decides before the app's other rules, ✓ included, and reaches the daemon without confusing one before 1.6.0.
final class VPNOnlyRuleTests: XCTestCase {
    let app = "/Applications/Foo.app"
    let main = "/Applications/Foo.app/Contents/MacOS/Foo"
    let updater = "/Applications/Foo.app/Contents/MacOS/Foo Updater"

    private func conn(_ offVPN: Bool?, exe: String? = nil, address: String = "203.0.113.5", port: Int = 443) -> Connection {
        Connection(process: ProcessIdentity(path: app), executable: exe ?? main, address: address, port: port, offVPN: offVPN)
    }

    private lazy var vpnOnly = Rule(verdict: .deny, processPath: app, requireVPN: true)

    func testMatchesOnlyWhatCertainlyLeavesOutsideATunnel() {
        XCTAssertTrue(vpnOnly.matches(conn(true)))
        XCTAssertFalse(vpnOnly.matches(conn(false)), "through a tunnel")
        XCTAssertFalse(vpnOnly.matches(conn(nil)), "route not known: not cut")
        XCTAssertTrue(vpnOnly.matches(conn(true), assuming: [.remote]), "an unconnected socket off the VPN")
        let one = Rule(verdict: .deny, processPath: app, executable: updater, requireVPN: true)
        XCTAssertTrue(one.matches(conn(true, exe: updater)))
        XCTAssertFalse(one.matches(conn(true)), "for one process only")
    }

    func testItIsNotTheAppsCrossAndSaysWhatItDoes() {
        XCTAssertFalse(vpnOnly.isWholeApp, "never blocks the app as a whole (denied-apps.txt)")
        XCTAssertNil(vpnOnly.effectiveListLevel)
        XCTAssertTrue(vpnOnly.hasCondition)
        XCTAssertTrue(vpnOnly.summary.hasSuffix("any server, unless through a VPN"), vpnOnly.summary)
    }

    func testEncodingKeepsOlderFilesAsTheyWere() throws {
        let plain = try JSONEncoder().encode(Rule(verdict: .deny, processPath: app))
        XCTAssertFalse(String(decoding: plain, as: UTF8.self).contains("requireVPN"), "written only when set")
        let data = try JSONEncoder().encode(vpnOnly)
        XCTAssertTrue(try JSONDecoder().decode(Rule.self, from: data).requireVPN)
        let old = #"{"id":"6F9619FF-8B86-D011-B42D-00CF4FC964FF","verdict":"deny","processPath":"/Applications/Foo.app"}"#
        XCTAssertFalse(try JSONDecoder().decode(Rule.self, from: Data(old.utf8)).requireVPN, "a file from before 1.6.0")
        // Every other field still round-trips through the hand-written encoder.
        let full = Rule(verdict: .allow, processPath: app, signingID: "com.foo", teamID: "TEAM1", executable: main, listLevel: .connection,
                        remoteHost: "api.example.com", ports: 443...443, proto: .udp, enabled: false, approved: false, lifetime: .untilQuit,
                        profileID: UUID(), groupID: UUID(), createdAt: Date(timeIntervalSince1970: 1_700_000_000), note: "n")
        XCTAssertEqual(try JSONDecoder().decode(Rule.self, from: JSONEncoder().encode(full)), full)
    }

    func testItDecidesBeforeEveryAllow() {
        let rules = [vpnOnly,
                     Rule(verdict: .allow, processPath: app, listLevel: .app),
                     Rule(verdict: .allow, processPath: app, executable: main, listLevel: .process),
                     Rule(verdict: .allow, processPath: app, executable: main, listLevel: .connection, remoteAddress: "203.0.113.5", ports: 443...443, proto: .tcp)]
        let e = RuleEngine(rules: rules, defaultVerdict: .ask)
        XCTAssertEqual(e.decide(conn(true)).verdict, .deny, "a ✓ never lifts the kill switch")
        XCTAssertEqual(e.decide(conn(true)).rule?.requireVPN, true)
        XCTAssertEqual(e.decide(conn(false)).verdict, .allow, "through the VPN the rows' ✓ decide")
        XCTAssertEqual(e.decide(conn(false)).rule?.listLevel, .connection)
        // Through the VPN, nothing else decides: the default does.
        XCTAssertEqual(RuleEngine(rules: [vpnOnly], defaultVerdict: .ask).decide(conn(false)).verdict, .ask)
        // An app ✗ still cuts what goes through the VPN.
        XCTAssertEqual(RuleEngine(rules: [vpnOnly, Rule(verdict: .deny, processPath: app, listLevel: .app)], defaultVerdict: .allow).decide(conn(false)).verdict, .deny)
    }

    func testTheDaemonFileKeepsConditionalRulesApart() throws {
        let allow = Rule(verdict: .allow, processPath: app, listLevel: .app)
        let d = DaemonRules(rules: [vpnOnly, allow])
        XCTAssertEqual(d.rules, [allow])
        XCTAssertEqual(d.conditionalRules, [vpnOnly])
        XCTAssertTrue(d.hasProcessDenies)
        let decoded = try XCTUnwrap(DaemonRules.decode(d.encoded()))
        XCTAssertEqual(decoded.conditionalRules.map(\.requireVPN), [true])
        XCTAssertEqual(decoded.allRules.count, 2)

        // A helper before 1.6.0 reads `rules` only: it sees no deny, so it never cuts the whole app.
        struct OldFile: Decodable { var rules: [Rule] }
        let decoder = JSONDecoder(); decoder.dateDecodingStrategy = .iso8601
        let old = try decoder.decode(OldFile.self, from: d.encoded())
        XCTAssertFalse(old.rules.contains { $0.verdict == .deny })
    }

    func testTheDaemonsJudgeCutsOnlyOffTheVPN() {
        let j = SocketJudge(DaemonRules(rules: [vpnOnly, Rule(verdict: .allow, processPath: app, listLevel: .app)],
                                        signatures: [app: .init(signingID: "com.foo", teamID: "TEAM1")]))
        XCTAssertTrue(j.needsRoute)
        XCTAssertTrue(j.watches(app: app, executable: updater), "every process of the app")
        XCTAssertTrue(j.denies(app: app, executable: main, address: "203.0.113.5", port: 443, proto: .tcp, offVPN: true))
        XCTAssertTrue(j.denies(app: app, executable: updater, address: "", port: 0, proto: .udp, offVPN: true), "unconnected, off the VPN")
        XCTAssertFalse(j.denies(app: app, executable: main, address: "203.0.113.5", port: 443, proto: .tcp, offVPN: false))
        XCTAssertFalse(j.denies(app: app, executable: main, address: "203.0.113.5", port: 443, proto: .tcp), "not known")
        XCTAssertTrue(j.isLocal("192.168.1.20"))
        XCTAssertFalse(j.isLocal("203.0.113.5"))
        XCTAssertFalse(SocketJudge(DaemonRules(rules: [Rule(verdict: .deny, processPath: app, listLevel: .app)])).needsRoute)
    }
}
