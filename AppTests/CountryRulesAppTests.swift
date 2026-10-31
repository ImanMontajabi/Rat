import XCTest
import RatFilterCore
import RatMonitor
@testable import Rat

/// Country rules (#45) in the app: Rat's pass looks every server up in the City database it shows on the map, cuts
/// the sockets to a denied country (an app's ✓ does not lift it), never a local one, and names the same database in
/// the daemon's file so the helper finds the same countries.
@MainActor
final class CountryRulesAppTests: XCTestCase {
    let app = "/Applications/Foo.app"
    let main = "/Applications/Foo.app/Contents/MacOS/Foo"

    private func tempDir() throws -> URL {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("rat-country-\(UUID())")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        addTeardownBlock { try? FileManager.default.removeItem(at: dir) }
        return dir
    }

    private func settledNames(_ addresses: [String]) -> HostNames {
        let names = HostNames(resolve: { _ in nil })
        for a in addresses { _ = names.lookup(a) }
        let deadline = Date().addingTimeInterval(5)
        while !addresses.allSatisfy({ names.lookup($0).settled }), Date() < deadline { RunLoop.current.run(until: Date().addingTimeInterval(0.02)) }
        return names
    }

    /// A ledger with the City database: the bundled one, else the one scripts/fetch-geoip.sh puts in the repo.
    private func ledger(_ dir: URL, names: [String]) throws -> Ledger {
        let l = Ledger(directory: dir, helperInstalled: true, names: settledNames(names))
        if l.geo.loadedFile(.city) == nil {
            let repo = URL(fileURLWithPath: #filePath).deletingLastPathComponent().appendingPathComponent("../App/Vendor/dbip-city-lite.mmdb").standardized.path
            try XCTSkipUnless(FileManager.default.fileExists(atPath: repo), "no City database")
            try l.geo.use(.city, path: repo)
        }
        try XCTSkipUnless(l.geo.countryCode("46.4.0.1") == "DE" && l.geo.countryCode("194.109.6.66") == "NL", "the database places the test addresses elsewhere")
        return l
    }

    private func tcp(_ remote: String, port: Int) -> ObservedConnection {
        ObservedConnection(pid: 900, processPath: main, proto: .tcp, remoteAddress: remote, remotePort: 443, localPort: port, tcpState: "ESTABLISHED",
                           localAddress: "192.168.178.39")
    }

    func testRatsPassCutsTheDeniedCountryOnly() async throws {
        let dir = try tempDir()
        let l = try ledger(dir, names: ["46.4.0.1", "194.109.6.66"])
        let conns = [tcp("46.4.0.1", port: 52000), tcp("194.109.6.66", port: 52001), tcp("192.168.178.1", port: 52002)]
        l.setPolicy(.allow, for: app)
        l.rules.upsert(l.rules.newCountryRule("DE", app: app))
        await l.ingest(conns, [])
        l.refreshEnforcement()
        let entry = try XCTUnwrap(l.apps.first { $0.identity.ruleKey == app })
        XCTAssertEqual(entry.remotes.first { $0.address == "46.4.0.1" }?.country, "DE")
        XCTAssertEqual(entry.remotes.first { $0.address == "46.4.0.1" }?.verdict, .deny, "the app's ✓ does not lift it")
        XCTAssertEqual(entry.remotes.first { $0.address == "194.109.6.66" }?.verdict, .allow)
        XCTAssertNil(entry.remotes.first { $0.address == "192.168.178.1" }?.country, "the router is in no country")
        XCTAssertEqual(try String(contentsOf: dir.appendingPathComponent("denied-ports.txt"), encoding: .utf8), "52000\n")
        XCTAssertTrue(l.deniedAppPaths.isEmpty, "never the whole app")

        // The daemon reads the same database, and gets the rule apart from what a helper before 1.6.0 reads.
        let d = try XCTUnwrap(DaemonRules.decode(Data(contentsOf: dir.appendingPathComponent("deny-rules.json"))))
        XCTAssertEqual(d.geoDatabase, l.geo.loadedFile(.city)?.path)
        XCTAssertEqual(d.conditionalRules.map(\.country), ["DE"])
        XCTAssertTrue(SocketJudge(d).needsCountry)

        // The rule gone: nothing is cut and the daemon is not told about a database.
        l.rules.ruleSet.rules.removeAll { $0.country != nil }
        await l.ingest(conns, [])
        l.refreshEnforcement()
        XCTAssertEqual(try String(contentsOf: dir.appendingPathComponent("denied-ports.txt"), encoding: .utf8), "")
        XCTAssertNil(try XCTUnwrap(DaemonRules.decode(Data(contentsOf: dir.appendingPathComponent("deny-rules.json")))).geoDatabase)
    }

    func testACountryRuleForAnyProcessCutsEveryApp() async throws {
        let dir = try tempDir()
        let l = try ledger(dir, names: ["46.4.0.1"])
        l.rules.upsert(l.rules.newCountryRule("DE", app: nil))
        let other = ObservedConnection(pid: 901, processPath: "/Applications/Bar.app/Contents/MacOS/Bar", proto: .udp, remoteAddress: "46.4.0.1",
                                       remotePort: 443, localPort: 52010, tcpState: nil, localAddress: "192.168.178.39")
        await l.ingest([tcp("46.4.0.1", port: 52011), other], [])
        l.refreshEnforcement()
        XCTAssertEqual(try String(contentsOf: dir.appendingPathComponent("denied-ports.txt"), encoding: .utf8), "52010\n52011\n")
    }

    func testTheRulesAboutAConnectionListItsCountrysRule() throws {
        let m = RulesModel(directory: try tempDir())
        let r = m.newCountryRule("de", app: app)
        XCTAssertEqual(r.country, "DE"); XCTAssertEqual(r.verdict, .deny); XCTAssertEqual(r.profileID, m.ruleSet.activeProfileID)
        m.upsert(r)
        let inGermany = RulesModel.Target(app: app, executable: main, endpoint: .init(host: nil, address: "46.4.0.1", port: 443, proto: .tcp, country: "DE"))
        let inNetherlands = RulesModel.Target(app: app, executable: main, endpoint: .init(host: nil, address: "194.109.6.66", port: 443, proto: .tcp, country: "NL"))
        XCTAssertEqual(m.rules(for: inGermany).map(\.id), [r.id])
        XCTAssertTrue(m.rules(for: inNetherlands).isEmpty)
        XCTAssertEqual(m.rules(for: RulesModel.Target(app: app)).map(\.id), [r.id], "the app's rules")
        XCTAssertNil(m.policy(for: app), "the app's ✗/✓ stays unset")
    }

    func testCountryNamesAndFlags() {
        XCTAssertEqual(Countries.label("DE"), "🇩🇪 " + Countries.name("DE"))
        let codes = Countries.all.map(\.code)
        XCTAssertTrue(codes.contains("DE") && codes.contains("US") && codes.contains("NL"))
        XCTAssertFalse(codes.contains("ZZ"))
        XCTAssertEqual(Set(codes).count, codes.count)
        XCTAssertTrue(codes.allSatisfy { Rule.countryCode($0) == $0 }, "every choice is a code a rule keeps")
        XCTAssertGreaterThan(codes.count, 200)
    }

    func testLocalAddressesAreInNoCountry() throws {
        let l = try ledger(try tempDir(), names: [])
        for a in ["", "127.0.0.1", "::1", "192.168.1.1", "10.0.0.1", "fe80::1", "224.0.0.251"] { XCTAssertNil(l.geo.countryCode(a), a) }
        XCTAssertEqual(l.geo.countryCode("46.4.0.1"), "DE")
    }
}
