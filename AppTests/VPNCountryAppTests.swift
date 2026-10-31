import XCTest
import RatFilterCore
import RatMonitor
import RatEnforce
@testable import Rat

/// "Only through a VPN in <country>" (#45) in the app: the ledger finds where each tunnel leads from its client's
/// outside connection, keeps the sockets through a tunnel to the named country, cuts those to a tunnel elsewhere and
/// those outside every tunnel, never a local one, and hands the daemon the database to find the same.
@MainActor
final class VPNCountryAppTests: XCTestCase {
    let app = "/Applications/Foo.app"
    let main = "/Applications/Foo.app/Contents/MacOS/Foo"
    let client = "/Library/Application Support/Windscribe/bin/windscribewireguard"

    private func tempDir() throws -> URL {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("rat-vpncountry-\(UUID())")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        addTeardownBlock { try? FileManager.default.removeItem(at: dir) }
        return dir
    }

    private func ledger(_ dir: URL, names: [String]) throws -> Ledger {
        let hostNames = HostNames(resolve: { _ in nil })
        for a in names { _ = hostNames.lookup(a) }
        let deadline = Date().addingTimeInterval(5)
        while !names.allSatisfy({ hostNames.lookup($0).settled }), Date() < deadline { RunLoop.current.run(until: Date().addingTimeInterval(0.02)) }
        let l = Ledger(directory: dir, helperInstalled: true, names: hostNames)
        if l.geo.loadedFile(.city) == nil {
            let repo = URL(fileURLWithPath: #filePath).deletingLastPathComponent().appendingPathComponent("../App/Vendor/dbip-city-lite.mmdb").standardized.path
            try XCTSkipUnless(FileManager.default.fileExists(atPath: repo), "no City database")
            try l.geo.use(.city, path: repo)
        }
        try XCTSkipUnless(l.geo.countryCode("46.4.0.1") == "DE" && l.geo.countryCode("194.109.6.66") == "NL", "the database places the test addresses elsewhere")
        return l
    }

    private func conn(_ pid: Int32, _ path: String, _ remote: String, port: Int, local: String, proto: ObservedConnection.Proto = .tcp) -> ObservedConnection {
        ObservedConnection(pid: pid, processPath: path, proto: proto, remoteAddress: remote, remotePort: 443, localPort: port,
                           tcpState: proto == .tcp ? "ESTABLISHED" : nil, localAddress: local)
    }

    /// Windscribe's tunnel utun420 carried over UDP to a server in `server`'s country.
    private func pass(_ l: Ledger, carrier: String) async {
        l.routes.set(tunnelAddresses: ["100.127.80.66": "utun420"], tunnelNames: ["utun420": "Windscribe"], proxies: [],
                     tunnelClients: [client: "Windscribe"], tunnelOwners: ["utun420": client])
        await l.ingest([conn(700, client, carrier, port: 53000, local: "192.168.178.39", proto: .udp),
                        conn(900, main, "203.0.113.8", port: 52000, local: "100.127.80.66"),     // through the tunnel
                        conn(900, main, "198.51.100.3", port: 52001, local: "192.168.178.39"),   // outside it
                        conn(900, main, "192.168.178.1", port: 52002, local: "192.168.178.39")], [])  // the router
        l.refreshEnforcement()
    }

    private func ports(_ dir: URL) throws -> String { try String(contentsOf: dir.appendingPathComponent("denied-ports.txt"), encoding: .utf8) }

    func testKeepsATunnelToTheCountryAndCutsOneElsewhere() async throws {
        let dir = try tempDir()
        let l = try ledger(dir, names: ["203.0.113.8", "198.51.100.3", "46.4.0.1", "194.109.6.66"])
        l.setPolicy(.allow, for: app)
        l.rules.setVPNOnly(true, for: RulesModel.Target(app: app), country: "DE")
        await pass(l, carrier: "46.4.0.1")
        XCTAssertEqual(l.tunnelServers["utun420"], .country("DE"), "Windscribe's server is in Germany")
        XCTAssertEqual(l.tunnelCarriers["utun420"], ["46.4.0.1"])
        XCTAssertEqual(try ports(dir), "52001\n", "only the socket outside the tunnel")
        let entry = try XCTUnwrap(l.apps.first { $0.identity.ruleKey == app })
        XCTAssertEqual(entry.remotes.first { $0.address == "203.0.113.8" }?.verdict, .allow)

        // The VPN moves to the Netherlands: the socket through it is cut too, the router never.
        await pass(l, carrier: "194.109.6.66")
        XCTAssertEqual(l.tunnelServers["utun420"], .country("NL"))
        XCTAssertEqual(try ports(dir), "52000\n52001\n")
        XCTAssertEqual(l.apps.first { $0.identity.ruleKey == app }?.remotes.first { $0.address == "203.0.113.8" }?.verdict, .deny)

        // The daemon gets the rule and the database.
        let d = try XCTUnwrap(DaemonRules.decode(Data(contentsOf: dir.appendingPathComponent("deny-rules.json"))))
        XCTAssertEqual(d.conditionalRules.compactMap(\.vpnCountry), ["DE"])
        XCTAssertEqual(d.geoDatabase, l.geo.loadedFile(.city)?.path)
        XCTAssertTrue(SocketJudge(d).needsVPNCountry)
    }

    func testATunnelWhoseServerCannotBePlacedIsCut() async throws {
        let dir = try tempDir()
        let l = try ledger(dir, names: ["203.0.113.8", "198.51.100.3"])
        l.rules.setVPNOnly(true, for: RulesModel.Target(app: app), country: "DE")
        await pass(l, carrier: "192.0.2.1")   // a documentation address: in no country
        XCTAssertEqual(l.tunnelServers["utun420"], .unknown)
        XCTAssertEqual(try ports(dir), "52000\n52001\n")

        // Any VPN: through the tunnel is fine, wherever it leads.
        l.rules.setVPNCountry(nil, for: RulesModel.Target(app: app))
        await pass(l, carrier: "192.0.2.1")
        XCTAssertEqual(try ports(dir), "52001\n")
        XCTAssertNil(try XCTUnwrap(DaemonRules.decode(Data(contentsOf: dir.appendingPathComponent("deny-rules.json")))).geoDatabase,
                     "no country named: the daemon is not told about a database")
    }

    /// While the helper runs, its scan is the one read: it sees a VPN client running as root (Windscribe's WireGuard,
    /// whose server only its pinned route names), and a tunnel it has not scanned yet is cut by neither.
    func testTheHelpersScanDecidesWhileItRuns() async throws {
        let dir = try tempDir()
        let l = try ledger(dir, names: ["203.0.113.8", "198.51.100.3", "46.4.0.1"])
        l.setPolicy(.allow, for: app)
        l.rules.setVPNOnly(true, for: RulesModel.Target(app: app), country: "DE")
        func status(_ servers: [String: [String]]?) throws {
            let enc = JSONEncoder(); enc.dateEncodingStrategy = .secondsSince1970
            try enc.encode(EnforcerStatus(pid: 1, updated: Date(), pfEnabled: true, anchorHooked: true, deniedApps: [:], blockedPorts: 0,
                                          countryLookup: true, tunnelServers: servers))
                .write(to: dir.appendingPathComponent("enforcer-status.json"))
            l.enforcer.refreshStatus()
        }
        // The rule was just made: the helper has not scanned the tunnel. The client's own socket (seen here) is not read.
        try status(nil)
        await pass(l, carrier: "194.109.6.66")
        XCTAssertNil(l.tunnelServers["utun420"], "not placed yet")
        XCTAssertEqual(try ports(dir), "52001\n", "only the socket outside the tunnel")
        XCTAssertEqual(VPNCountryNote.now(l.tunnelServers, up: ["utun420"], names: ["utun420": "Windscribe"]), "Now: Windscribe → finding its server…")

        // Its scan is in: a server in Germany, the one route Windscribe pinned.
        try status(["utun420": ["46.4.0.1"]])
        await pass(l, carrier: "194.109.6.66")
        XCTAssertEqual(l.tunnelServers["utun420"], .country("DE"))
        XCTAssertEqual(try ports(dir), "52001\n")
        try status(["utun420": []])
        await pass(l, carrier: "46.4.0.1")
        XCTAssertEqual(l.tunnelServers["utun420"], .unknown, "the helper found no carrier")
        XCTAssertEqual(try ports(dir), "52000\n52001\n")
    }

    func testTheModelKeepsOneRuleAndItsCountry() throws {
        let m = RulesModel(directory: try tempDir())
        let appRow = RulesModel.Target(app: app), process = RulesModel.Target(app: app, executable: main)
        m.setVPNOnly(true, for: appRow, country: "de")
        XCTAssertEqual(m.vpnCountry(appRow), "DE")
        XCTAssertEqual(m.vpnCountry(process), "DE", "a process follows its app's")
        m.setVPNCountry("NL", for: appRow)
        XCTAssertEqual(m.ruleSet.rules.filter(\.requireVPN).map(\.vpnCountry), ["NL"], "one rule, its country changed")
        m.setVPNCountry(nil, for: appRow)
        XCTAssertNil(m.vpnCountry(appRow))
        XCTAssertTrue(m.vpnOnly(appRow), "still on, for any VPN")
        m.setVPNCountry("NL", for: process)
        XCTAssertEqual(m.ruleSet.rules.count, 1, "a process without its own rule gets none from the picker")
        // A country rule with the VPN condition is not the switch's rule.
        m.ruleSet.rules.append(Rule(verdict: .deny, processPath: app, country: "FR", requireVPN: true))
        m.setVPNOnly(false, for: appRow)
        XCTAssertEqual(m.ruleSet.rules.map(\.country), ["FR"])
        XCTAssertEqual(VPNCountryNote.title("DE"), "Only through a VPN in " + Countries.label("DE"))
        XCTAssertEqual(VPNCountryNote.title(nil), "Only through a VPN")
        XCTAssertEqual(VPNCountryNote.now(["utun420": .country("NL"), "utun3": .unknown], names: ["utun420": "Windscribe"]),
                       "Now: utun3 → server not placed, Windscribe → " + Countries.label("NL"))
    }
}
