import XCTest
@testable import RatEnforce
import RatFilterCore
import RatGeo
import RatMonitor

/// Country rules (#45) in the daemon: it reads the City database Rat names (`DaemonRules.geoDatabase`) only when it
/// is a file the user could read anyway, looks each server up on the fast pass and blocks the local ports of the
/// sockets to the denied country, never an address. This test process is the app; pfctl is never run.
final class CountryEnforcementTests: XCTestCase {
    let exe = ConnectionSampler.path(of: getpid())
    var app: String { ProcessGrouping.owner(of: exe, responsiblePath: { nil }).ruleKey }

    /// Set RAT_GEOIP_DB to a DB-IP Lite City file (CI does), or keep the one scripts/fetch-geoip.sh puts in the repo.
    private func cityDB() throws -> String {
        if let p = ProcessInfo.processInfo.environment["RAT_GEOIP_DB"] { return p }
        let repo = URL(fileURLWithPath: #filePath).deletingLastPathComponent().appendingPathComponent("../../../App/Vendor/dbip-city-lite.mmdb").standardized.path
        try XCTSkipUnless(FileManager.default.fileExists(atPath: repo), "no City database (RAT_GEOIP_DB, or scripts/fetch-geoip.sh)")
        return repo
    }

    private func tempDir() throws -> URL {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("rat-enf-country-\(UUID())")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        addTeardownBlock { try? FileManager.default.removeItem(at: dir) }
        return dir
    }

    private func udp(to server: String?) throws -> Int {
        let fd = socket(AF_INET, SOCK_DGRAM, 0)
        addTeardownBlock { close(fd) }
        var addr = sockaddr_in(); addr.sin_family = sa_family_t(AF_INET); addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        if let server {
            inet_pton(AF_INET, server, &addr.sin_addr); addr.sin_port = UInt16(443).bigEndian
            let r = withUnsafePointer(to: &addr) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.connect(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) } }
            try XCTSkipIf(r != 0, "no route to \(server) here (errno \(errno))")
        } else {
            addr.sin_addr.s_addr = UInt32(0x7f000001).bigEndian
            _ = withUnsafePointer(to: &addr) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) } }
        }
        var bound = sockaddr_in(); var len = socklen_t(MemoryLayout<sockaddr_in>.size)
        _ = withUnsafeMutablePointer(to: &bound) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(fd, $0, &len) } }
        return Int(UInt16(bigEndian: bound.sin_port))
    }

    private func daemon(_ dir: URL, rules: DaemonRules) throws -> (EnforcerDaemon, String) {
        try "".write(to: dir.appendingPathComponent("denied.txt"), atomically: true, encoding: .utf8)
        try rules.encoded().write(to: dir.appendingPathComponent("deny-rules.json"))
        let status = dir.appendingPathComponent("status.json").path
        var s = EnforcerDaemon.Settings(deniedFile: dir.appendingPathComponent("denied.txt").path, statusFile: status)
        s.rulesFile = dir.appendingPathComponent("deny-rules.json").path
        s.anchor = "com.apple/rat-unittest"
        s.ownerUID = getuid()
        let d = EnforcerDaemon(settings: s, run: { _, _, _ in 0 },
                               capture: { _, args in args == ["-s", "info"] ? "Status: Enabled" : args == ["-s", "rules"] ? "anchor \"com.apple/*\" all" : "" })
        return (d, status)
    }

    private func status(_ path: String) throws -> EnforcerStatus {
        let dec = JSONDecoder(); dec.dateDecodingStrategy = .secondsSince1970
        return try dec.decode(EnforcerStatus.self, from: Data(contentsOf: URL(fileURLWithPath: path)))
    }

    func testTheDaemonCutsTheSocketsToTheDeniedCountryOnly() throws {
        let db = try cityDB()
        let g = try XCTUnwrap(GeoFile.open(db, ownerUID: getuid()))
        // DB-IP places these in Germany (Hetzner) and the Netherlands (XS4ALL); the test says so if a month moves them.
        try XCTSkipUnless(g.countryCode("46.4.0.1") == "DE" && g.countryCode("194.109.6.66") == "NL", "the database places the test addresses elsewhere")
        let dir = try tempDir()
        let germany = try udp(to: "46.4.0.1"), netherlands = try udp(to: "194.109.6.66"), loopback = try udp(to: nil)
        let rules = DaemonRules(rules: [Rule(verdict: .deny, processPath: app, country: "DE"), Rule(verdict: .allow, processPath: app, listLevel: .app)],
                                geoDatabase: db)
        let (d, statusPath) = try daemon(dir, rules: rules)
        XCTAssertTrue(d.tick(), "the app a country rule names is read on the fast pass")
        XCTAssertTrue(d.loadedPorts.contains(germany), "the app's ✓ does not lift it")
        XCTAssertFalse(d.loadedPorts.contains(netherlands))
        XCTAssertFalse(d.loadedPorts.contains(loopback), "loopback is in no country")
        XCTAssertTrue(d.deniedPIDs.isEmpty, "never the whole app")
        XCTAssertEqual(try status(statusPath).countryLookup, true)
    }

    /// Without a database the daemon cuts nothing for a country (Rat's own pass still does, through
    /// denied-ports.txt), and says so in its status.
    func testWithoutADatabaseNothingIsCutForACountry() throws {
        let dir = try tempDir()
        let germany = try udp(to: "46.4.0.1")
        let missing = dir.appendingPathComponent("none.mmdb").path
        let (d, statusPath) = try daemon(dir, rules: DaemonRules(rules: [Rule(verdict: .deny, processPath: app, country: "DE")], geoDatabase: missing))
        d.tick()
        XCTAssertFalse(d.loadedPorts.contains(germany))
        XCTAssertEqual(try status(statusPath).countryLookup, false)
        // No country rule: the status leaves it out.
        let (plain, plainStatus) = try daemon(try tempDir(), rules: DaemonRules(rules: [Rule(verdict: .deny, processPath: app, proto: .tcp)]))
        plain.tick()
        XCTAssertNil(try status(plainStatus).countryLookup)
    }

    func testOpensOnlyARegularFileTheUserCouldRead() throws {
        let db = try cityDB()
        XCTAssertNotNil(GeoFile.open(db, ownerUID: getuid()))
        let dir = try tempDir()
        let link = dir.appendingPathComponent("link.mmdb").path
        try FileManager.default.createSymbolicLink(atPath: link, withDestinationPath: db)
        XCTAssertNil(GeoFile.open(link, ownerUID: getuid()), "a symlink is never followed")
        XCTAssertNil(GeoFile.open(dir.path, ownerUID: getuid()), "a folder")
        let junk = dir.appendingPathComponent("junk.mmdb")
        try Data(repeating: 0x41, count: 4096).write(to: junk)
        XCTAssertNil(GeoFile.open(junk.path, ownerUID: getuid()), "not a database")
        let empty = dir.appendingPathComponent("empty.mmdb")
        try Data().write(to: empty)
        XCTAssertNil(GeoFile.open(empty.path, ownerUID: getuid()))
        XCTAssertNil(GeoFile.open(dir.appendingPathComponent("none.mmdb").path, ownerUID: getuid()))

        // Who may name what: root reads any file, so the user's file must be the user's to read.
        func st(mode: mode_t, uid: uid_t) -> stat { var s = stat(); s.st_mode = mode; s.st_uid = uid; return s }
        XCTAssertTrue(GeoFile.readable(st(mode: S_IFREG | 0o644, uid: 0), by: 501), "everyone can read it")
        XCTAssertTrue(GeoFile.readable(st(mode: S_IFREG | 0o600, uid: 501), by: 501), "the user's own")
        XCTAssertFalse(GeoFile.readable(st(mode: S_IFREG | 0o600, uid: 0), by: 501), "root's private file")
        XCTAssertFalse(GeoFile.readable(st(mode: S_IFREG | 0o640, uid: 502), by: 501), "another user's")
        XCTAssertFalse(GeoFile.readable(st(mode: S_IFREG | 0o600, uid: 501), by: nil), "no owner given: only what everyone can read")
        XCTAssertFalse(GeoFile.readable(st(mode: S_IFREG | 0o200, uid: 501), by: 501), "not readable by its owner")
        XCTAssertFalse(GeoFile.readable(st(mode: S_IFCHR | 0o644, uid: 0), by: 501), "a device")
    }

    /// A new file at the same path (an updated Rat.app) is a different file.
    func testANewFileAtTheSamePathIsOpenedAgain() throws {
        let dir = try tempDir()
        let path = dir.appendingPathComponent("city.mmdb")
        try Data([1]).write(to: path)
        let first = GeoFile.identity(path.path)
        XCTAssertEqual(GeoFile.identity(path.path), first)
        try FileManager.default.removeItem(at: path)
        try Data([2]).write(to: dir.appendingPathComponent("other"))
        try Data([1]).write(to: path)
        XCTAssertNotEqual(GeoFile.identity(path.path), first)
    }
}
