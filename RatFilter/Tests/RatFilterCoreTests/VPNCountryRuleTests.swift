import XCTest
@testable import RatFilterCore

/// "Only through a VPN in <country>" (`Rule.vpnCountry`, #45): besides what leaves outside a tunnel, it cuts what goes
/// through a tunnel to a server elsewhere or to one whose country could not be told; it never cuts a socket nobody
/// placed in a tunnel, and old files stay as they were.
final class VPNCountryRuleTests: XCTestCase {
    let app = "/Applications/Foo.app"
    let main = "/Applications/Foo.app/Contents/MacOS/Foo"

    private func conn(offVPN: Bool?, server: TunnelServer?) -> Connection {
        Connection(process: ProcessIdentity(path: app), executable: main, address: "203.0.113.5", port: 443, offVPN: offVPN, tunnelServer: server)
    }

    private let inGermany = Rule(verdict: .deny, processPath: "/Applications/Foo.app", requireVPN: true, vpnCountry: "de")

    func testMatchesOnlyATunnelElsewhereOrUnplaced() {
        XCTAssertEqual(inGermany.vpnCountry, "DE", "normalized")
        XCTAssertTrue(inGermany.matches(conn(offVPN: true, server: nil)), "outside every tunnel, as without a country")
        XCTAssertFalse(inGermany.matches(conn(offVPN: false, server: .country("DE"))), "through a VPN to Germany")
        XCTAssertTrue(inGermany.matches(conn(offVPN: false, server: .country("NL"))), "through a VPN to the Netherlands")
        XCTAssertTrue(inGermany.matches(conn(offVPN: false, server: .unknown)), "through a VPN whose server cannot be placed")
        XCTAssertFalse(inGermany.matches(conn(offVPN: false, server: nil)), "local, or not looked at: never cut")
        XCTAssertFalse(inGermany.matches(conn(offVPN: nil, server: nil)), "route not known")
        let any = Rule(verdict: .deny, processPath: app, requireVPN: true)
        XCTAssertFalse(any.matches(conn(offVPN: false, server: .country("NL"))), "any VPN: the country does not matter")
        XCTAssertFalse(any.matches(conn(offVPN: false, server: .unknown)))
    }

    func testOnlyWithRequireVPN() {
        XCTAssertNil(Rule(verdict: .deny, processPath: app, vpnCountry: "DE").vpnCountry, "no VPN condition, no VPN country")
        XCTAssertNil(Rule(verdict: .deny, processPath: app, requireVPN: true, vpnCountry: "Germany").vpnCountry)
        XCTAssertNil(Rule(verdict: .deny, processPath: app, requireVPN: true, vpnCountry: "ZZ").vpnCountry)
        var r = inGermany; r.requireVPN = false
        XCTAssertFalse(String(decoding: try! JSONEncoder().encode(r), as: UTF8.self).contains("vpnCountry"), "a leftover country is not written")
        XCTAssertFalse(inGermany.isWholeApp)
        XCTAssertTrue(inGermany.hasCondition)
    }

    func testSummaryNamesTheCountry() {
        XCTAssertTrue(inGermany.summary.hasSuffix("any server, unless through a VPN in DE"), inGermany.summary)
        XCTAssertTrue(inGermany.summary(country: { $0 == "DE" ? "Germany" : $0 }).hasSuffix("unless through a VPN in Germany"))
        XCTAssertTrue(Rule(verdict: .deny, processPath: app, requireVPN: true).summary.hasSuffix("any server, unless through a VPN"))
    }

    func testDecidesFirstLikeAnyVPNOnlyRule() {
        let rules = [inGermany, Rule(verdict: .allow, processPath: app, listLevel: .app),
                     Rule(verdict: .allow, processPath: app, executable: main, listLevel: .connection, remoteAddress: "203.0.113.5", ports: 443...443, proto: .tcp)]
        let e = RuleEngine(rules: rules, defaultVerdict: .ask)
        XCTAssertEqual(e.decide(conn(offVPN: false, server: .country("NL"))).verdict, .deny, "a ✓ never lifts it")
        XCTAssertEqual(e.decide(conn(offVPN: false, server: .country("NL"))).rule?.vpnCountry, "DE")
        XCTAssertEqual(e.decide(conn(offVPN: false, server: .country("DE"))).verdict, .allow, "through Germany the rows' ✓ decide")
    }

    func testEncodingKeepsOlderFilesAsTheyWere() throws {
        let plain = String(decoding: try JSONEncoder().encode(Rule(verdict: .deny, processPath: app, requireVPN: true)), as: UTF8.self)
        XCTAssertFalse(plain.contains("vpnCountry"), "written only when set")
        XCTAssertEqual(try JSONDecoder().decode(Rule.self, from: JSONEncoder().encode(inGermany)), inGermany)
        let v160 = #"{"id":"6F9619FF-8B86-D011-B42D-00CF4FC964FF","verdict":"deny","processPath":"/Applications/Foo.app","requireVPN":true}"#
        XCTAssertNil(try JSONDecoder().decode(Rule.self, from: Data(v160.utf8)).vpnCountry, "a VPN-only rule from before")
        let hand = #"{"id":"6F9619FF-8B86-D011-B42D-00CF4FC964FF","verdict":"deny","processPath":"/Applications/Foo.app","requireVPN":true,"vpnCountry":"nl"}"#
        XCTAssertEqual(try JSONDecoder().decode(Rule.self, from: Data(hand.utf8)).vpnCountry, "NL")
        let stray = #"{"id":"6F9619FF-8B86-D011-B42D-00CF4FC964FF","verdict":"deny","processPath":"/Applications/Foo.app","vpnCountry":"NL"}"#
        XCTAssertNil(try JSONDecoder().decode(Rule.self, from: Data(stray.utf8)).vpnCountry, "no condition: dropped")
    }

    func testTheDaemonFileAndJudge() throws {
        let d = DaemonRules(rules: [inGermany, Rule(verdict: .allow, processPath: app, listLevel: .app)], geoDatabase: "/x.mmdb")
        XCTAssertEqual(d.conditionalRules.map(\.vpnCountry), ["DE"])
        XCTAssertEqual(try XCTUnwrap(DaemonRules.decode(d.encoded())).conditionalRules.map(\.vpnCountry), ["DE"])
        let j = SocketJudge(d)
        XCTAssertTrue(j.needsVPNCountry); XCTAssertTrue(j.needsRoute); XCTAssertTrue(j.needsGeo); XCTAssertFalse(j.needsCountry)
        func denies(_ offVPN: Bool, _ server: TunnelServer?, address: String = "203.0.113.5") -> Bool {
            j.denies(app: app, executable: main, address: address, port: 443, proto: .tcp, offVPN: offVPN, tunnelServer: server)
        }
        XCTAssertFalse(denies(false, .country("DE")))
        XCTAssertTrue(denies(false, .country("NL")))
        XCTAssertTrue(denies(false, .unknown))
        XCTAssertFalse(denies(false, nil), "no database, or a tunnel not scanned yet: not cut")
        XCTAssertTrue(denies(true, nil), "outside the tunnel")
        XCTAssertFalse(denies(false, .unknown, address: "192.168.178.1"), "the local network is never cut")
        XCTAssertFalse(SocketJudge(DaemonRules(rules: [Rule(verdict: .deny, processPath: app, requireVPN: true)])).needsVPNCountry)

        // A helper from before the VPN country reads the rule without it: it cuts only what leaves outside a tunnel,
        // a part of what the rule cuts.
        struct OldRule: Decodable { var requireVPN: Bool?; var verdict: String }
        struct OldFile: Decodable { var conditionalRules: [OldRule] }
        let decoder = JSONDecoder(); decoder.dateDecodingStrategy = .iso8601
        XCTAssertEqual(try decoder.decode(OldFile.self, from: d.encoded()).conditionalRules.first?.requireVPN, true)
    }
}
