import XCTest
@testable import RatFilterCore

/// Rules for the servers in one country (`Rule.country`, #45): they match the country the offline database gives,
/// never a server whose country is not known, sit between any server and a domain in specificity, a ✓ does not lift
/// one that denies, and they reach the daemon apart from what a helper before 1.6.0 reads.
final class CountryRuleTests: XCTestCase {
    let app = "/Applications/Foo.app"
    let main = "/Applications/Foo.app/Contents/MacOS/Foo"
    let updater = "/Applications/Foo.app/Contents/MacOS/Foo Updater"

    private func conn(_ country: String?, exe: String? = nil, host: String? = nil, address: String = "203.0.113.5", port: Int = 443,
                      offVPN: Bool? = nil) -> Connection {
        Connection(process: ProcessIdentity(path: app), executable: exe ?? main, host: host, address: address, port: port, offVPN: offVPN, country: country)
    }

    func testCodesAreNormalizedOrDropped() {
        XCTAssertEqual(Rule(verdict: .deny, country: "de").country, "DE")
        XCTAssertEqual(Rule(verdict: .deny, country: " nl ").country, "NL")
        for bad in ["", "D", "DEU", "1A", "Ü1", "D-", "ZZ", "zz"] { XCTAssertNil(Rule(verdict: .deny, country: bad).country, bad) }
        XCTAssertEqual(Rule.countryCode("us"), "US")
        XCTAssertNil(Rule.countryCode(nil))
    }

    func testMatchesTheServersCountryOnly() {
        let r = Rule(verdict: .deny, processPath: app, country: "DE")
        XCTAssertTrue(r.matches(conn("DE")))
        XCTAssertFalse(r.matches(conn("NL")))
        XCTAssertFalse(r.matches(conn(nil)), "a server whose country is not known is in none")
        XCTAssertTrue(r.matches(conn(nil), assuming: [.country]), "the daemon without a database: only for rules that allow")
        let withPort = Rule(verdict: .deny, processPath: app, ports: 443...443, country: "DE")
        XCTAssertFalse(withPort.matches(conn("DE", port: 80)))
        let forOne = Rule(verdict: .deny, processPath: app, executable: updater, country: "DE")
        XCTAssertTrue(forOne.matches(conn("DE", exe: updater)))
        XCTAssertFalse(forOne.matches(conn("DE")))
        XCTAssertTrue(Rule(verdict: .deny, country: "DE").isForAnyProcess)
    }

    func testIsNotTheAppsCrossAndSaysWhere() {
        let r = Rule(verdict: .deny, processPath: app, country: "DE")
        XCTAssertFalse(r.isWholeApp, "never blocks the app as a whole (denied-apps.txt)")
        XCTAssertNil(r.effectiveListLevel)
        XCTAssertTrue(r.hasCondition)
        XCTAssertTrue(r.summary.hasSuffix("any server in DE"), r.summary)
        XCTAssertTrue(Rule(verdict: .deny, processPath: app, remoteDomain: "example.com", country: "DE").summary.hasSuffix("*.example.com in DE"))
    }

    func testSpecificitySitsBetweenAnyServerAndADomain() {
        let any = Rule(verdict: .allow, processPath: app)
        let country = Rule(verdict: .deny, processPath: app, country: "DE")
        let domain = Rule(verdict: .allow, processPath: app, remoteDomain: "example.com")
        XCTAssertLessThan(any.specificity, country.specificity)
        XCTAssertLessThan(country.specificity, domain.specificity)
        let e = RuleEngine(rules: [country, domain, Rule(verdict: .allow, processPath: app, remoteDomain: "*")], defaultVerdict: .ask)
        XCTAssertEqual(e.decide(conn("DE", host: "cdn.example.com")).verdict, .allow, "a domain is more specific than a country")
        XCTAssertEqual(e.decide(conn("DE", host: "other.example.org")).verdict, .deny)
        XCTAssertEqual(e.decide(conn("NL", host: "other.example.org")).verdict, .allow)
        // Two countries never overlap; an allow for one host in a denied country wins.
        let host = Rule(verdict: .allow, processPath: app, remoteHost: "api.example.org")
        XCTAssertEqual(RuleEngine(rules: [country, host], defaultVerdict: .ask).decide(conn("DE", host: "api.example.org")).verdict, .allow)
        // Same specificity: deny over allow, whatever the order.
        let allowDE = Rule(verdict: .allow, processPath: app, country: "DE", createdAt: Date(timeIntervalSince1970: 2_000_000_000))
        XCTAssertEqual(RuleEngine(rules: [allowDE, country], defaultVerdict: .ask).decide(conn("DE")).verdict, .deny)
    }

    func testAnAllowDoesNotLiftACountryDeny() {
        let deny = Rule(verdict: .deny, processPath: app, country: "DE")
        for allow in [Rule(verdict: .allow, processPath: app, listLevel: .app),
                      Rule(verdict: .allow, processPath: app, executable: main, listLevel: .process),
                      Rule(verdict: .allow, processPath: app, executable: main, listLevel: .connection, remoteAddress: "203.0.113.5", ports: 443...443, proto: .tcp)] {
            let e = RuleEngine(rules: [allow, deny], defaultVerdict: .allow)
            XCTAssertEqual(e.decide(conn("DE")).verdict, .deny, "\(allow.listLevel!)'s ✓")
            XCTAssertEqual(e.decide(conn("DE")).rule?.country, "DE")
            XCTAssertEqual(e.decide(conn("NL")).verdict, .allow)
            XCTAssertEqual(e.decide(conn(nil)).verdict, .allow, "not known: the ✓ decides")
        }
        // A deny for every app's servers in a country, too.
        let everyone = Rule(verdict: .deny, country: "DE")
        XCTAssertEqual(RuleEngine(rules: [everyone, Rule(verdict: .allow, processPath: app, listLevel: .app)], defaultVerdict: .allow).decide(conn("DE")).verdict, .deny)
        // An allow for the country more specific than the deny lifts it (one domain of the country).
        let domainDE = Rule(verdict: .allow, processPath: app, remoteDomain: "example.com", country: "DE")
        let e = RuleEngine(rules: [Rule(verdict: .allow, processPath: app, listLevel: .app), deny, domainDE], defaultVerdict: .allow)
        XCTAssertEqual(e.decide(conn("DE", host: "a.example.com")).verdict, .allow)
        XCTAssertEqual(e.decide(conn("DE", host: "a.example.org")).verdict, .deny)
    }

    func testAnAppsCrossStaysOverACountryAllow() {
        let e = RuleEngine(rules: [Rule(verdict: .deny, processPath: app, listLevel: .app), Rule(verdict: .allow, processPath: app, country: "DE")], defaultVerdict: .allow)
        XCTAssertEqual(e.decide(conn("DE")).verdict, .deny, "the ✗ decides first")
        // Without a ✗ the country allow decides over Silent Mode's deny.
        XCTAssertEqual(RuleEngine(rules: [Rule(verdict: .allow, processPath: app, country: "DE")], defaultVerdict: .deny).decide(conn("DE")).verdict, .allow)
    }

    func testVPNOnlyStillDecidesFirst() {
        let rules = [Rule(verdict: .allow, processPath: app, country: "DE"), Rule(verdict: .deny, processPath: app, requireVPN: true)]
        let e = RuleEngine(rules: rules, defaultVerdict: .ask)
        XCTAssertEqual(e.decide(conn("DE", offVPN: true)).verdict, .deny)
        XCTAssertEqual(e.decide(conn("DE", offVPN: false)).verdict, .allow)
        XCTAssertEqual(e.decide(conn("NL", offVPN: false)).verdict, .ask)
    }

    func testEncodingKeepsOlderFilesAsTheyWere() throws {
        let plain = try JSONEncoder().encode(Rule(verdict: .deny, processPath: app))
        XCTAssertFalse(String(decoding: plain, as: UTF8.self).contains("country"), "written only when set")
        let r = Rule(verdict: .deny, processPath: app, country: "DE")
        XCTAssertEqual(try JSONDecoder().decode(Rule.self, from: JSONEncoder().encode(r)), r)
        let hand = #"{"id":"6F9619FF-8B86-D011-B42D-00CF4FC964FF","verdict":"deny","country":"nl"}"#
        XCTAssertEqual(try JSONDecoder().decode(Rule.self, from: Data(hand.utf8)).country, "NL", "a hand edit in lower case")
        let junk = #"{"id":"6F9619FF-8B86-D011-B42D-00CF4FC964FF","verdict":"deny","country":"Germany"}"#
        XCTAssertNil(try JSONDecoder().decode(Rule.self, from: Data(junk.utf8)).country)
    }

    func testTheDaemonFileKeepsCountryRulesApart() throws {
        let deny = Rule(verdict: .deny, processPath: app, country: "DE")
        let allow = Rule(verdict: .allow, processPath: app, listLevel: .app)
        let d = DaemonRules(rules: [deny, allow], geoDatabase: "/Applications/Rat.app/Contents/Resources/Vendor/dbip-city-lite.mmdb")
        XCTAssertEqual(d.rules, [allow])
        XCTAssertEqual(d.conditionalRules, [deny])
        let decoded = try XCTUnwrap(DaemonRules.decode(d.encoded()))
        XCTAssertEqual(decoded.geoDatabase, d.geoDatabase)
        XCTAssertEqual(decoded.conditionalRules.map(\.country), ["DE"])
        XCTAssertNil(try XCTUnwrap(DaemonRules.decode(DaemonRules(rules: [allow]).encoded())).geoDatabase)

        // A helper before 1.6.0 reads `rules` only: it sees no deny, so it never cuts the whole app.
        struct OldFile: Decodable { var rules: [Rule] }
        let decoder = JSONDecoder(); decoder.dateDecodingStrategy = .iso8601
        XCTAssertFalse(try decoder.decode(OldFile.self, from: d.encoded()).rules.contains { $0.verdict == .deny })
    }

    func testTheDaemonsJudgeCutsOnlyWhatIsCertainlyInTheCountry() {
        let j = SocketJudge(DaemonRules(rules: [Rule(verdict: .deny, processPath: app, country: "DE"), Rule(verdict: .allow, processPath: app, listLevel: .app)],
                                        signatures: [app: .init(signingID: "com.foo", teamID: "TEAM1")], localRanges: "100.64.0.0/10"))
        XCTAssertTrue(j.needsCountry)
        XCTAssertFalse(j.needsRoute)
        XCTAssertTrue(j.watches(app: app, executable: updater))
        XCTAssertTrue(j.denies(app: app, executable: main, address: "203.0.113.5", port: 443, proto: .tcp, country: "DE", countryKnown: true))
        XCTAssertFalse(j.denies(app: app, executable: main, address: "203.0.113.5", port: 443, proto: .tcp, country: "NL", countryKnown: true))
        XCTAssertFalse(j.denies(app: app, executable: main, address: "203.0.113.5", port: 443, proto: .tcp, country: nil, countryKnown: true), "not in the database")
        XCTAssertFalse(j.denies(app: app, executable: main, address: "203.0.113.5", port: 443, proto: .tcp, country: "DE", countryKnown: false), "no database")
        XCTAssertFalse(j.denies(app: app, executable: main, address: "", port: 0, proto: .udp, country: "DE", countryKnown: true), "unconnected: no server")
        // Inside the local network, whatever a database says (the user's own ranges included): never a country.
        for local in ["192.168.178.1", "127.0.0.1", "::1", "fe80::1", "10.0.0.2", "100.64.1.1"] {
            XCTAssertFalse(j.denies(app: app, executable: main, address: local, port: 443, proto: .tcp, country: "DE", countryKnown: true), local)
        }
        XCTAssertFalse(SocketJudge(DaemonRules(rules: [Rule(verdict: .deny, processPath: app, listLevel: .app)])).needsCountry)
        XCTAssertFalse(SocketJudge(DaemonRules(rules: [Rule(verdict: .deny, processPath: app, country: "DE", enabled: false)])).needsCountry)
    }

    /// An allow for a country lifts the daemon's deny only when the country is known: with no database, the
    /// daemon counts it as matching (it might be in the country), so it never cuts what Rat's pass would allow.
    func testWithoutADatabaseACountryAllowCountsAsMatching() {
        let j = SocketJudge(DaemonRules(rules: [Rule(verdict: .deny, processPath: app, proto: .tcp), Rule(verdict: .allow, processPath: app, ports: 443...443, country: "DE")],
                                        signatures: [app: .init(signingID: nil, teamID: nil)]))
        XCTAssertFalse(j.denies(app: app, executable: main, address: "203.0.113.5", port: 443, proto: .tcp, country: nil, countryKnown: false))
        XCTAssertTrue(j.denies(app: app, executable: main, address: "203.0.113.5", port: 443, proto: .tcp, country: "NL", countryKnown: true))
        XCTAssertFalse(j.denies(app: app, executable: main, address: "203.0.113.5", port: 443, proto: .tcp, country: "DE", countryKnown: true))
    }
}
