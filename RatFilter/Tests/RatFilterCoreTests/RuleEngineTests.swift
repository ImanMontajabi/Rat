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

    func testUnapprovedAndDisabledIgnored() {
        let e = RuleEngine(rules: [Rule(verdict: .deny, approved: false), Rule(verdict: .deny, enabled: false)])
        XCTAssertEqual(e.evaluate(conn("a.com")), .ask)
    }

    func testStoreRoundTrip() throws {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("rules-\(UUID()).json")
        let store = RuleStore(url: url)
        try store.save([Rule(verdict: .deny, remoteDomain: "a.com", ports: 80...443)])
        XCTAssertEqual(try store.load().first?.ports, 80...443)
    }
}
