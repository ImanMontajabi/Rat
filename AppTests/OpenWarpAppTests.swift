import XCTest
import RatFilterCore
import RatMonitor
import RatEnforce
@testable import Rat

/// OpenWarp (the companion WARP client) in the ledger: its root helper is listed under the app, its unconnected
/// carrier socket becomes its connection to the endpoint its status names (with the socket's bytes), placed at the
/// data centre the tunnel exits at, and "Only through a VPN in Germany" sees Germany, never the anycast prefix's
/// Canada. Without an exit, the endpoint is placed nowhere.
@MainActor
final class OpenWarpAppTests: XCTestCase {
    let helper = OpenWarpStatus.helperPath
    let bundle = OpenWarpStatus.appPath
    let endpoint = "162.159.198.2"
    let app = "/Applications/Foo.app"
    let main = "/Applications/Foo.app/Contents/MacOS/Foo"

    private func tempDir() throws -> URL {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("rat-openwarp-\(UUID())")
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
        return l
    }

    private func status(colo: String? = "DUS", loc: String? = "DE") -> OpenWarpStatus {
        OpenWarpStatus(pid: 627, connected: true, mode: "warp", transport: "MASQUE (HTTP/3)", interface: "utun4",
                       endpoint: .init(address: endpoint, port: 443), colo: colo, loc: loc)
    }

    /// OpenWarp's helper as Rat's root snapshot shows it (`p627 / PUDP / n*:53818`), and an app whose traffic goes
    /// through the tunnel.
    private func pass(_ l: Ledger, _ warp: OpenWarpStatus?, carried: (UInt64, UInt64) = (2_381_253, 2_207_109)) async {
        l.routes.set(tunnelAddresses: ["172.16.0.2": "utun4"], tunnelNames: ["utun4": "OpenWarp"], proxies: [],
                     tunnelClients: [helper: "OpenWarp"], tunnelOwners: ["utun4": helper])
        await l.ingest([ObservedConnection(pid: 627, processPath: helper, proto: .udp, remoteAddress: "", remotePort: 0, localPort: 53818, tcpState: nil),
                        ObservedConnection(pid: 900, processPath: main, proto: .tcp, remoteAddress: "203.0.113.8", remotePort: 443, localPort: 52000,
                                           tcpState: "ESTABLISHED", localAddress: "172.16.0.2")],
                       [], flows: [FlowCounter(pid: 627, proto: .udp, localPort: 53818, remoteAddress: "", remotePort: 0, bytesIn: carried.0, bytesOut: carried.1)],
                       openWarp: warp)
        l.refreshEnforcement()
    }

    private func carrier(_ l: Ledger) -> RemoteHost? {
        l.apps.first { $0.identity.ruleKey == bundle }?.remotes.first { $0.carrier }
    }

    func testTheCarrierIsOpenWarpsConnectionToItsEndpoint() async throws {
        let l = try ledger(try tempDir(), names: [endpoint, "203.0.113.8"])
        await pass(l, status())
        let entry = try XCTUnwrap(l.apps.first { $0.identity.ruleKey == bundle }, "the helper is listed under OpenWarp")
        XCTAssertNil(l.apps.first { $0.identity.id == helper }, "not as a tool of its own")
        XCTAssertEqual(entry.identity.name, "OpenWarp")
        let r = try XCTUnwrap(carrier(l))
        XCTAssertEqual(r.address, endpoint); XCTAssertEqual(r.port, 443); XCTAssertEqual(r.proto, "UDP")
        XCTAssertEqual(r.process, "com.local.openwarp")
        XCTAssertEqual(r.bytesIn, 2_381_253, "the socket's bytes, from nettop's flow without a remote port"); XCTAssertEqual(r.bytesOut, 2_207_109)
        XCTAssertEqual(r.route, .vpnServer(name: "OpenWarp"))
        XCTAssertEqual(r.geo?.city, "Düsseldorf", "the data centre the tunnel exits at")
        XCTAssertEqual(r.geo?.countryCode, "DE")
        XCTAssertEqual(r.country, "DE")
        XCTAssertEqual(r.verdict, .allow, "judged like any connection (silent allow)")
        XCTAssertNil(entry.ruleTarget(process: r.process, remote: r), "no ✗/✓: a rule about it could not be enforced on its socket")
        XCTAssertEqual(l.exitLabel(for: r), "Cloudflare data centre DUS")

        // The next pass: its rate is the socket's growth.
        await pass(l, status(), carried: (2_381_253 + 150_000, 2_207_109 + 15_000))
        XCTAssertGreaterThan(try XCTUnwrap(carrier(l)).rateIn, 0)
    }

    func testWithoutAnExitTheEndpointIsPlacedNowhere() async throws {
        let l = try ledger(try tempDir(), names: [endpoint, "203.0.113.8"])
        try XCTSkipUnless(l.geo.countryCode(endpoint) != nil, "the database has no country for the endpoint")
        // OpenWarp 0.1, or its lookup switched off: no colo/loc.
        await pass(l, status(colo: nil, loc: nil))
        let r = try XCTUnwrap(carrier(l))
        XCTAssertNil(r.geo, "not where the anycast prefix is registered (\(l.geo.countryCode(endpoint) ?? "-"))")
        XCTAssertNil(r.country)
        XCTAssertEqual(l.tunnelServers["utun4"], .unknown)
        XCTAssertEqual(l.exitLabel(for: r), "Unknown (anycast: Cloudflare answers from the nearest data centre)")
    }

    func testWithoutOpenWarpNothingIsInvented() async throws {
        let l = try ledger(try tempDir(), names: [endpoint, "203.0.113.8"])
        await pass(l, nil)
        XCTAssertNil(carrier(l), "a socket without a peer stays without one")
        XCTAssertNotNil(l.apps.first { $0.identity.ruleKey == bundle }, "the helper is still listed under OpenWarp")
    }

    func testOnlyThroughAVPNInGermanySeesGermany() async throws {
        let dir = try tempDir()
        let l = try ledger(dir, names: [endpoint, "203.0.113.8"])
        l.setPolicy(.allow, for: app)
        l.rules.setVPNOnly(true, for: RulesModel.Target(app: app), country: "DE")
        await pass(l, status())
        XCTAssertEqual(l.tunnelServers["utun4"], .country("DE"), "OpenWarp's exit, not the endpoint's database country")
        XCTAssertEqual(l.tunnelCarriers["utun4"], [endpoint])
        XCTAssertEqual(l.apps.first { $0.identity.ruleKey == app }?.remotes.first { $0.address == "203.0.113.8" }?.verdict, .allow)
        XCTAssertEqual(try String(contentsOf: dir.appendingPathComponent("denied-ports.txt"), encoding: .utf8), "", "nothing cut")

        // The tunnel exits in the Netherlands: the app's socket through it is cut.
        await pass(l, status(colo: "AMS", loc: "NL"))
        XCTAssertEqual(l.tunnelServers["utun4"], .country("NL"))
        XCTAssertEqual(l.apps.first { $0.identity.ruleKey == app }?.remotes.first { $0.address == "203.0.113.8" }?.verdict, .deny)
        XCTAssertEqual(try String(contentsOf: dir.appendingPathComponent("denied-ports.txt"), encoding: .utf8), "52000\n")
    }

    func testDenyingOpenWarpCutsItsCarrier() async throws {
        let dir = try tempDir()
        let l = try ledger(dir, names: [endpoint, "203.0.113.8"])
        l.setPolicy(.deny, for: bundle)
        await pass(l, status())
        XCTAssertEqual(carrier(l)?.verdict, .deny)
        XCTAssertTrue(l.deniedAppPaths.contains(bundle), "the helper denies the app as a whole, its helper with it")
    }

    // MARK: places and icons

    func testAirportsPlaceCloudflareDataCentres() throws {
        let dus = try XCTUnwrap(Airports.place("DUS"))
        XCTAssertEqual(dus.city, "Düsseldorf"); XCTAssertEqual(dus.countryCode, "DE")
        XCTAssertEqual(dus.latitude, 51.29, accuracy: 0.05); XCTAssertEqual(dus.longitude, 6.77, accuracy: 0.05)
        XCTAssertNotNil(Airports.place("fra"), "any case")
        XCTAssertNil(Airports.place("ZZZ"))
        let exit = try XCTUnwrap(Airports.exit(colo: "DUS", loc: "DE"))
        XCTAssertEqual(exit.place, "🇩🇪 Düsseldorf, \(Countries.name("DE"))")
        XCTAssertEqual(Airports.parse("DUS\t51.2895\t6.7668\tDE\tDüsseldorf\nbad line\nXX\t1\t1\tDE\tX\nBAD\t95\t1\tDE\tX\n").keys.sorted(), ["DUS"])
    }

    func testTheIconComesFromWhereverOpenWarpIs() {
        XCTAssertEqual(AppIdentity.iconPath(bundle, exists: { _ in true }, locate: { _ in "/Users/me/Apps/OpenWarp.app" }), bundle)
        XCTAssertEqual(AppIdentity.iconPath(bundle, exists: { _ in false }, locate: { $0 == "local.openwarp.app" ? "/Users/me/Apps/OpenWarp.app" : nil }),
                       "/Users/me/Apps/OpenWarp.app")
        XCTAssertEqual(AppIdentity.iconPath("/Applications/Other.app", exists: { _ in false }, locate: { _ in "/x.app" }), "/Applications/Other.app")
    }
}
