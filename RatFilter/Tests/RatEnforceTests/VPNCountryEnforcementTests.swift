import XCTest
@testable import RatEnforce
import RatFilterCore
import RatGeo
import RatMonitor

/// "Only through a VPN in <country>" (#45) in the daemon: on the fast pass it finds where the tunnel a socket goes
/// through leads and cuts the socket when that is elsewhere or cannot be told. This test process is the app; what is
/// expected follows this Mac's tunnels now (none: everything to the Internet is outside one). pfctl is never run.
final class VPNCountryEnforcementTests: XCTestCase {
    let exe = ConnectionSampler.path(of: getpid())
    var app: String { ProcessGrouping.owner(of: exe, responsiblePath: { nil }).ruleKey }

    private func cityDB() throws -> String {
        if let p = ProcessInfo.processInfo.environment["RAT_GEOIP_DB"] { return p }
        let repo = URL(fileURLWithPath: #filePath).deletingLastPathComponent().appendingPathComponent("../../../App/Vendor/dbip-city-lite.mmdb").standardized.path
        try XCTSkipUnless(FileManager.default.fileExists(atPath: repo), "no City database (RAT_GEOIP_DB, or scripts/fetch-geoip.sh)")
        return repo
    }

    private func udp(to server: String) throws -> (port: Int, local: String) {
        let fd = socket(AF_INET, SOCK_DGRAM, 0)
        addTeardownBlock { close(fd) }
        var addr = sockaddr_in(); addr.sin_family = sa_family_t(AF_INET); addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        inet_pton(AF_INET, server, &addr.sin_addr); addr.sin_port = UInt16(443).bigEndian
        let r = withUnsafePointer(to: &addr) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.connect(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) } }
        try XCTSkipIf(r != 0, "no route to \(server) here (errno \(errno))")
        var bound = sockaddr_in(); var len = socklen_t(MemoryLayout<sockaddr_in>.size)
        _ = withUnsafeMutablePointer(to: &bound) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(fd, $0, &len) } }
        var buf = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
        let local = inet_ntop(AF_INET, &bound.sin_addr, &buf, socklen_t(buf.count)).map { String(cString: $0) } ?? ""
        return (Int(UInt16(bigEndian: bound.sin_port)), local)
    }

    /// The daemon judging this process's socket by a rule naming `country`, once its tunnel scan is in (status).
    private func run(country: String, db: String, port: Int) throws -> (cut: Bool, status: EnforcerStatus?) {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("rat-enf-vpncountry-\(UUID())")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        try "".write(to: dir.appendingPathComponent("denied.txt"), atomically: true, encoding: .utf8)
        let rules = DaemonRules(rules: [Rule(verdict: .deny, processPath: app, requireVPN: true, vpnCountry: country),
                                        Rule(verdict: .allow, processPath: app, listLevel: .app)], geoDatabase: db)
        try rules.encoded().write(to: dir.appendingPathComponent("deny-rules.json"))
        let statusPath = dir.appendingPathComponent("status.json").path
        var s = EnforcerDaemon.Settings(deniedFile: dir.appendingPathComponent("denied.txt").path, statusFile: statusPath)
        s.rulesFile = dir.appendingPathComponent("deny-rules.json").path
        s.anchor = "com.apple/rat-unittest"
        s.ownerUID = getuid()
        let d = EnforcerDaemon(settings: s, run: { _, _, _ in 0 },
                               capture: { _, args in args == ["-s", "info"] ? "Status: Enabled" : args == ["-s", "rules"] ? "anchor \"com.apple/*\" all" : "" })
        let dec = JSONDecoder(); dec.dateDecodingStrategy = .secondsSince1970
        var status: EnforcerStatus?
        let tunnels = Set(NetworkRoutes.tunnelAddresses().values)
        // The tunnels' clients are scanned off the watch loop: pass until the status has every tunnel's country.
        let start = Date()
        repeat {
            d.tick(now: Date())
            status = (try? Data(contentsOf: URL(fileURLWithPath: statusPath))).flatMap { try? dec.decode(EnforcerStatus.self, from: $0) }
            if Set(status?.tunnelCountries?.keys.map { $0 } ?? []).isSuperset(of: tunnels) { break }
            Thread.sleep(forTimeInterval: 0.25)
        } while Date().timeIntervalSince(start) < 8
        d.tick(now: Date().addingTimeInterval(1))
        return (d.loadedPorts.contains(port), status)
    }

    func testCutsWhatGoesElsewhereOrOutsideATunnel() throws {
        let db = try cityDB()
        let geo = try XCTUnwrap(GeoFile.open(db, ownerUID: getuid()))
        let socket = try udp(to: "203.0.113.5")
        let tunnels = NetworkRoutes.tunnelAddresses()
        let iface = NetworkRoutes.tunnelInterface(localAddress: socket.local, remoteAddress: "203.0.113.5", tunnels: tunnels, isLocal: { LocalNetwork.contains($0) },
                                                  route: { $0.map(NetworkRoutes.routeInterface(to:)) ?? NetworkRoutes.internetTunnel() })
        // Where this socket's tunnel leads, as this test process can see it (a VPN client running as root is not
        // visible to it: then it cannot be placed, and the daemon running as this user cuts the socket too).
        var leads: String?
        if let iface, let owner = NetworkRoutes.tunnelOwnerProcesses(relays: true)[iface] {
            let carriers = NetworkRoutes.carrierServers(owner: ConnectionSampler.connections(of: owner.pid), relays: owner.relays.flatMap(ConnectionSampler.connections(of:)),
                                                        tunnels: tunnels, isLocal: { LocalNetwork.contains($0) },
                                                        pinned: { NetworkRoutes.pinnedServers(for: iface, isLocal: { LocalNetwork.contains($0) }) })
            leads = NetworkRoutes.serverCountry(carriers, lookup: geo.countryCode)
        }
        let other = leads == "IS" ? "NZ" : "IS"
        let elsewhere = try run(country: other, db: db, port: socket.port)
        XCTAssertTrue(elsewhere.cut, "a tunnel to \(leads ?? "an unplaced server"), or none (\(iface ?? "outside every tunnel")), is not one to \(other)")
        XCTAssertNotNil(elsewhere.status?.tunnelServers, "the status says where the tunnels lead")
        XCTAssertEqual(elsewhere.status?.countryLookup, true)
        if let leads {
            let there = try run(country: leads, db: db, port: socket.port)
            XCTAssertFalse(there.cut, "through \(iface!) to a server in \(leads)")
            XCTAssertEqual(there.status?.tunnelCountries?[iface!], leads)
        }
    }

    /// Without a database nothing is cut for the VPN's country: only what leaves outside every tunnel.
    func testWithoutADatabaseOnlyTheVPNConditionCuts() throws {
        let socket = try udp(to: "203.0.113.5")
        let tunnels = NetworkRoutes.tunnelAddresses()
        let outside = NetworkRoutes.leavesOutsideTunnel(localAddress: socket.local, remoteAddress: "203.0.113.5", tunnels: tunnels, isLocal: { LocalNetwork.contains($0) },
                                                        route: { $0.map(NetworkRoutes.routeInterface(to:)) ?? NetworkRoutes.internetTunnel() })
        let r = try run(country: "IS", db: "/nonexistent/city.mmdb", port: socket.port)
        XCTAssertEqual(r.cut, outside)
        XCTAssertEqual(r.status?.countryLookup, false)
        XCTAssertNil(r.status?.tunnelCountries, "no country is told without a database")
    }
}
