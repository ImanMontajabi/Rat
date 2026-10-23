import XCTest
import RatFilterCore
import RatMonitor
import RatEnforce
import RatGeo
@testable import Rat

/// 1.2.0: the five feature issues (#1 to #5).
@MainActor
final class Release120Tests: XCTestCase {
    // MARK: #1 port names

    func testUsualServiceLabels() {
        XCTAssertEqual(serviceSuffix(proto: "TCP", port: 443), " · HTTPS")
        XCTAssertEqual(serviceSuffix(proto: "UDP", port: 443), " · QUIC")
        XCTAssertEqual(serviceSuffix(proto: "TCP", port: 5223), " · APN")
        XCTAssertEqual(serviceSuffix(proto: "TCP", port: 51234), "")
    }

    // MARK: #5 subprocess per connection, services in the macOS row

    func testConnectionsKeepTheirProcessAndSystemServicesTheirName() async throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("rat-120-\(UUID())")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let ledger = Ledger(directory: dir, helperInstalled: true)
        let app = "/Applications/Demo/Foo.app"
        let conns = [
            ObservedConnection(pid: 900, processPath: app + "/Contents/Frameworks/Foo Helper.app/Contents/MacOS/Foo Helper", proto: .tcp,
                               remoteAddress: "203.0.113.10", remotePort: 443, localPort: 60001, tcpState: "ESTABLISHED"),
            ObservedConnection(pid: 901, processPath: app + "/Contents/MacOS/Foo", proto: .tcp,
                               remoteAddress: "203.0.113.10", remotePort: 443, localPort: 60002, tcpState: "ESTABLISHED"),
            ObservedConnection(pid: 50, processPath: "/usr/sbin/mDNSResponder", proto: .udp,
                               remoteAddress: "198.51.100.53", remotePort: 53, localPort: 60003, tcpState: nil),
            ObservedConnection(pid: 51, processPath: "/usr/libexec/nsurlsessiond", proto: .tcp,
                               remoteAddress: "203.0.113.20", remotePort: 443, localPort: 60004, tcpState: "ESTABLISHED"),
        ]
        await ledger.ingest(conns, [])
        let foo = try XCTUnwrap(ledger.apps.first { $0.id == app })
        XCTAssertEqual(Set(foo.remotes.map { "\($0.process ?? "") \($0.pid ?? 0)" }), ["Foo Helper 900", "Foo 901"],
                       "the same server from two processes is two rows, each with its process")
        XCTAssertEqual(Set(foo.remotes.map(\.id)).count, 2)
        let mac = try XCTUnwrap(ledger.apps.first { $0.id == "macOS" })
        XCTAssertEqual(Set(mac.remotes.compactMap(\.process)), ["mDNSResponder", "nsurlsessiond"], "one macOS row, services named inside")
        XCTAssertNotNil(SharedServices.note(for: "mDNSResponder"))
        XCTAssertNil(SharedServices.note(for: "Foo Helper"))
        XCTAssertNil(mac.identity.mainProcessName, "every service in the macOS row is shown by name")
        let calculator = AppIdentity.resolve(processPath: "/System/Applications/Calculator.app/Contents/MacOS/Calculator")
        XCTAssertEqual(calculator.mainProcessName, "Calculator")
    }

    // MARK: #4 network owner (ASN)

    func testBundledASNDatabaseNamesNetworks() throws {
        let url = try XCTUnwrap(Bundle.main.url(forResource: "dbip-asn-lite", withExtension: "mmdb", subdirectory: "Vendor"),
                                "Contents/Resources/Vendor/dbip-asn-lite.mmdb must be bundled; run scripts/fetch-geoip.sh")
        XCTAssertFalse(url.path.isEmpty)
        let g = GeoService()
        XCTAssertTrue(g.networksAvailable)
        XCTAssertEqual(g.network("1.1.1.1")?.number, 13335)
        XCTAssertTrue(g.network("8.8.8.8")?.label.hasPrefix("AS15169 ") ?? false, g.network("8.8.8.8")?.label ?? "nil")
        XCTAssertNil(g.network("192.168.1.10"))
    }

    func testLedgerShowsTheNetworkOfEachServer() async throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("rat-120-\(UUID())")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let ledger = Ledger(directory: dir, helperInstalled: true)
        guard ledger.geo.networksAvailable else { throw XCTSkip("no ASN database") }
        await ledger.ingest([ObservedConnection(pid: 900, processPath: "/Applications/Demo/Foo.app/Contents/MacOS/Foo", proto: .tcp,
                                                remoteAddress: "1.1.1.1", remotePort: 443, localPort: 60010, tcpState: "ESTABLISHED")], [])
        let foo = try XCTUnwrap(ledger.apps.first { $0.id == "/Applications/Demo/Foo.app" })
        XCTAssertTrue(foo.remotes.first?.network?.hasPrefix("AS13335 ") ?? false)
        XCTAssertEqual(ledger.networks().first?.count, 1)
    }

    // MARK: #3 choose and update the GeoIP databases

    /// A one-node IPv4 .mmdb whose every address maps to `record` (same layout as RatGeo's test fixture).
    static func tinyMMDB(_ record: [UInt8], type: String, built: UInt64 = 1_790_000_000) -> Data {
        func str(_ s: String) -> [UInt8] { (s.utf8.count < 29 ? [UInt8(0x40 | s.utf8.count)] : [0x40 | 29, UInt8(s.utf8.count - 29)]) + Array(s.utf8) }
        var d = Data([0, 0, 17, 0, 0, 17]) + Data(count: 16) + Data(record)
        d += [0xAB, 0xCD, 0xEF] + Array("MaxMind.com".utf8)
        d += [0xe5] + str("node_count") + [0xc1, 1] + str("record_size") + [0xa1, 24] + str("ip_version") + [0xa1, 4]
        d += str("database_type") + str(type) + str("build_epoch") + [0x08, 0x02] + withUnsafeBytes(of: built.bigEndian, Array.init)
        return d
    }

    static func asnFixture(_ n: UInt32, _ org: String) -> Data {
        func str(_ s: String) -> [UInt8] { (s.utf8.count < 29 ? [UInt8(0x40 | s.utf8.count)] : [0x40 | 29, UInt8(s.utf8.count - 29)]) + Array(s.utf8) }
        return tinyMMDB([0xe2] + str("autonomous_system_number") + [0xc4] + withUnsafeBytes(of: n.bigEndian, Array.init)
                        + str("autonomous_system_organization") + str(org), type: "Test-ASN")
    }

    static func cityFixture() -> Data {
        func str(_ s: String) -> [UInt8] { [UInt8(0x40 | s.utf8.count)] + Array(s.utf8) }
        func dbl(_ v: Double) -> [UInt8] { [0x68] + withUnsafeBytes(of: v.bitPattern.bigEndian, Array.init) }
        let rec: [UInt8] = [0xe3]
            + str("location") + [0xe2] + str("latitude") + dbl(48.85) + str("longitude") + dbl(2.35)
            + str("city") + [0xe1] + str("names") + [0xe1] + str("en") + str("Testville")
            + str("country") + [0xe2] + str("names") + [0xe1] + str("en") + str("Testland") + str("iso_code") + str("TL")
        return tinyMMDB(rec, type: "Test-City")
    }

    private func geoSetup() throws -> (URL, GeoService, UserDefaults, () -> Void) {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("rat-120-geo-\(UUID())")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let suite = "rat-120-geo-\(UUID())"
        let defaults = try XCTUnwrap(UserDefaults(suiteName: suite))
        return (dir, GeoService(), defaults, { try? FileManager.default.removeItem(at: dir); UserDefaults.standard.removePersistentDomain(forName: suite) })
    }

    func testChosenDatabasesAreValidatedCopiedAndReloadedWithoutRestart() throws {
        let (dir, geo, defaults, cleanup) = try geoSetup()
        defer { cleanup() }
        let dbs = GeoDatabases(directory: dir, geo: geo, defaults: defaults)
        XCTAssertEqual(dbs.info[.asn]?.custom, false, "the bundled file is the default")

        let asn = dir.appendingPathComponent("mine-asn.mmdb")
        try Self.asnFixture(64500, "Test Networks").write(to: asn)
        try dbs.choose(.asn, file: asn)
        XCTAssertEqual(geo.network("8.8.8.8"), NetworkOwner(number: 64500, organization: "Test Networks"), "used at once, cache cleared")
        XCTAssertEqual(dbs.info[.asn]?.custom, true)
        XCTAssertEqual(dbs.info[.asn]?.type, "Test-ASN")
        XCTAssertEqual(dbs.info[.asn]?.built, Date(timeIntervalSince1970: 1_790_000_000))
        let stored = try XCTUnwrap(defaults.string(forKey: GeoDatabases.key(.asn)))
        XCTAssertTrue(FileManager.default.fileExists(atPath: dbs.folder.appendingPathComponent(stored).path), "copied into the data folder")

        // Rejected: garbage, and an ASN file offered as the city database. The current files stay in use.
        let junk = dir.appendingPathComponent("junk.mmdb")
        try Data("not a database".utf8).write(to: junk)
        XCTAssertThrowsError(try dbs.choose(.asn, file: junk))
        XCTAssertThrowsError(try dbs.choose(.city, file: asn))
        XCTAssertEqual(geo.network("8.8.8.8")?.number, 64500)

        let city = dir.appendingPathComponent("mine-city.mmdb")
        try Self.cityFixture().write(to: city)
        try dbs.choose(.city, file: city)
        XCTAssertEqual(geo.lookup("8.8.8.8")?.city, "Testville")

        // A second choice replaces the first file; "Use Bundled" deletes the copy.
        try Self.asnFixture(64501, "Other").write(to: asn)
        try dbs.choose(.asn, file: asn)
        XCTAssertFalse(FileManager.default.fileExists(atPath: dbs.folder.appendingPathComponent(stored).path))
        XCTAssertEqual(geo.network("8.8.8.8")?.number, 64501)
        dbs.useBundled(.asn)
        XCTAssertEqual(dbs.info[.asn]?.custom, false)
        XCTAssertNil(defaults.string(forKey: GeoDatabases.key(.asn)))
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: dbs.folder.path).filter { $0.hasPrefix("asn-") }, [])
    }

    func testMissingChosenFileFallsBackToTheBundledOne() throws {
        let (dir, geo, defaults, cleanup) = try geoSetup()
        defer { cleanup() }
        defaults.set("city-gone.mmdb", forKey: GeoDatabases.key(.city))
        let dbs = GeoDatabases(directory: dir, geo: geo, defaults: defaults)
        XCTAssertEqual(dbs.info[.city]?.custom, false)
        XCTAssertNotNil(dbs.lastError)
        XCTAssertTrue(geo.available)
    }

    func testDownloadLatestUnpacksAndSwitches() async throws {
        let (dir, geo, defaults, cleanup) = try geoSetup()
        defer { cleanup() }
        var asked: [URL] = []
        let dbs = GeoDatabases(directory: dir, geo: geo, defaults: defaults, download: { url in
            asked.append(url)
            guard asked.count == 2 else { throw URLError(.fileDoesNotExist) }   // this month's file is not out yet
            let raw = FileManager.default.temporaryDirectory.appendingPathComponent("rat-dl-\(UUID()).mmdb")
            try Self.asnFixture(64502, "Downloaded").write(to: raw)
            let p = Process(); p.executableURL = URL(fileURLWithPath: "/usr/bin/gzip"); p.arguments = ["-f", raw.path]
            try p.run(); p.waitUntilExit()
            return URL(fileURLWithPath: raw.path + ".gz")
        })
        await dbs.downloadLatest(.asn)
        XCTAssertNil(dbs.lastError)
        XCTAssertEqual(geo.network("8.8.8.8")?.number, 64502)
        XCTAssertEqual(asked.count, 2)
        XCTAssertTrue(asked[0].absoluteString.hasPrefix("https://download.db-ip.com/free/dbip-asn-lite-"))
        let now = ISO8601DateFormatter().date(from: "2026-01-15T00:00:00Z")!
        XCTAssertEqual(GeoDatabases.dbipURLs(.city, now: now).map(\.lastPathComponent), ["dbip-city-lite-2026-01.mmdb.gz", "dbip-city-lite-2025-12.mmdb.gz"])
        XCTAssertTrue(dbs.isStale(.init(custom: true, fileName: "x", type: "t", built: now), now: now.addingTimeInterval(100 * 86_400)))
        XCTAssertFalse(dbs.isStale(.init(custom: true, fileName: "x", type: "t", built: now), now: now.addingTimeInterval(10 * 86_400)))
    }

    // MARK: #2 connections through a VPN or a system proxy

    func testVPNAndSystemProxyRoutesAreMarkedPerSocket() async throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("rat-120-\(UUID())")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let ledger = Ledger(directory: dir, helperInstalled: true)
        ledger.routes.set(tunnelAddresses: ["10.64.0.2": "utun4"], tunnelNames: ["utun4": "Windscribe"],
                          proxies: [.init(kind: .https, host: "proxy.corp.example", port: 3128), .init(kind: .socks, host: "127.0.0.1", port: 7890)],
                          proxyAddresses: ["proxy.corp.example": ["198.51.100.7"]])
        let app = "/Applications/Demo/Foo.app/Contents/MacOS/Foo"
        func c(_ local: String, _ remote: String, _ port: Int, _ lport: Int) -> ObservedConnection {
            ObservedConnection(pid: 900, processPath: app, proto: .tcp, remoteAddress: remote, remotePort: port, localPort: lport, tcpState: "ESTABLISHED", localAddress: local)
        }
        await ledger.ingest([c("10.64.0.2", "203.0.113.30", 443, 60100),      // through the tunnel
                             c("192.168.178.39", "203.0.113.31", 443, 60101), // split tunnel: outside it
                             c("192.168.178.39", "198.51.100.7", 3128, 60102),
                             c("127.0.0.1", "127.0.0.1", 7890, 60103)], [])
        let foo = try XCTUnwrap(ledger.apps.first { $0.id == "/Applications/Demo/Foo.app" })
        func route(_ a: String) -> String? { foo.remotes.first { $0.address == a }?.route }
        XCTAssertEqual(route("203.0.113.30"), "via VPN (Windscribe)")
        XCTAssertNil(route("203.0.113.31"), "a split tunnel is told apart per socket")
        XCTAssertEqual(route("198.51.100.7"), "via System HTTPS Proxy (proxy.corp.example:3128)")
        XCTAssertEqual(route("127.0.0.1"), "via System SOCKS Proxy (127.0.0.1:7890)")
    }

    func testVPNNames() {
        let ext = "/Library/SystemExtensions/AB/com.windscribe.client.networkextension.systemextension/Contents/MacOS/com.windscribe.client.networkextension"
        XCTAssertEqual(RouteMarker.name(interface: "utun4", service: "My VPN", owner: ext), "Windscribe")
        XCTAssertEqual(RouteMarker.name(interface: "utun4", service: "Office", owner: "/usr/sbin/racoon"), "Office")
        XCTAssertEqual(RouteMarker.name(interface: "utun4", service: nil, owner: "/Applications/Calculator.app/Contents/MacOS/Calculator"), "Calculator")
        XCTAssertEqual(RouteMarker.name(interface: "utun7", service: nil, owner: nil), "utun7")
    }
}
