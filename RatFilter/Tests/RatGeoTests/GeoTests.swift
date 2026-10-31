import XCTest
@testable import RatGeo

final class GeoTests: XCTestCase {
    /// Set RAT_GEOIP_DB to a DB-IP Lite city .mmdb to run the database tests.
    private func db() throws -> GeoIP {
        guard let p = ProcessInfo.processInfo.environment["RAT_GEOIP_DB"] else { throw XCTSkip("RAT_GEOIP_DB not set") }
        return try GeoIP(path: p)
    }

    func testKnownAddresses() throws {
        let g = try db()
        XCTAssertEqual(g.locate("8.8.8.8")?.countryCode, "US")
        XCTAssertEqual(g.locate("1.1.1.1")?.countryCode.isEmpty, false)
        XCTAssertNotNil(g.locate("2001:4860:4860::8888"))
        XCTAssertNil(g.locate("not an ip"))
        let l = try XCTUnwrap(g.locate("8.8.8.8"))
        XCTAssertTrue((-90...90).contains(l.latitude) && (-180...180).contains(l.longitude))
    }

    func testPrivateAddressesNotLocated() throws {
        let g = try db()
        XCTAssertNil(g.locate("192.168.1.1"))
        XCTAssertNil(g.locate("127.0.0.1"))
    }

    /// What country rules match (#45): the record's ISO code in upper case, the same as `locate` gives, and none for
    /// what the database does not place.
    func testCountryCodes() throws {
        let g = try db()
        XCTAssertEqual(g.countryCode("8.8.8.8"), "US")
        for a in ["8.8.8.8", "1.1.1.1", "46.4.0.1", "194.109.6.66", "2001:4860:4860::8888"] {
            XCTAssertEqual(g.countryCode(a), g.locate(a)?.countryCode.uppercased(), a)
        }
        for a in ["192.168.1.1", "127.0.0.1", "::1", "fe80::1", "not an ip", ""] { XCTAssertNil(g.countryCode(a), a) }
    }

    func testRejectsGarbageFile() {
        XCTAssertThrowsError(try MMDB(data: Data("hello".utf8)))
    }

    func testTimeZoneParsing() {
        let tab = "DE\t+5230+01322\tEurope/Berlin\nUS\t+404251-0740023\tAmerica/New_York\n"
        let b = TimeZoneLocator.coordinates(forZone: "Europe/Berlin", zoneTab: tab)
        XCTAssertEqual(b?.lat ?? 0, 52.5, accuracy: 0.01)
        XCTAssertEqual(b?.lon ?? 0, 13.3667, accuracy: 0.01)
        let n = TimeZoneLocator.coordinates(forZone: "America/New_York", zoneTab: tab)
        XCTAssertEqual(n?.lat ?? 0, 40.714, accuracy: 0.01)
        XCTAssertEqual(n?.lon ?? 0, -74.006, accuracy: 0.01)
        XCTAssertNil(TimeZoneLocator.coordinates(forZone: "Nowhere/City", zoneTab: tab))
    }

    func testSystemZoneTabResolvesCurrentZone() {
        XCTAssertNotNil(TimeZoneLocator.coordinates(forZone: "Europe/Berlin"))
    }
}

/// 1.2.0: user-chosen database files are untrusted input to a hand-written reader.
final class MMDBRobustnessTests: XCTestCase {
    /// A minimal valid IPv4 database: one node whose both records point into the data section.
    static func tinyDatabase(record: [UInt8], ipVersion: UInt8 = 4, nodeCount: UInt8 = 1, databaseType: String = "Test-ASN") -> Data {
        var d = Data()
        // node 0: left and right record = nodeCount + 16 (data offset 0), record size 24
        let ptr = Int(nodeCount) + 16
        for _ in 0..<Int(nodeCount) { d += [UInt8(ptr >> 16), UInt8(ptr >> 8 & 0xff), UInt8(ptr & 0xff)] + [UInt8(ptr >> 16), UInt8(ptr >> 8 & 0xff), UInt8(ptr & 0xff)] }
        d += [UInt8](repeating: 0, count: 16)
        d += record
        d += [0xAB, 0xCD, 0xEF] + Array("MaxMind.com".utf8)
        func str(_ s: String) -> [UInt8] { [UInt8(0x40 | s.utf8.count)] + Array(s.utf8) }
        func u16(_ v: UInt8) -> [UInt8] { [0xa1, v] }
        func u32(_ v: UInt32) -> [UInt8] { [0xc4] + withUnsafeBytes(of: v.bigEndian, Array.init) }
        d += [0xe5]   // map, 5 entries
        d += str("node_count") + [0xc1, nodeCount]
        d += str("record_size") + u16(24)
        d += str("ip_version") + u16(ipVersion)
        d += str("database_type") + str(databaseType)
        d += str("build_epoch") + [0x08, 0x02] + withUnsafeBytes(of: UInt64(1_790_000_000).bigEndian, Array.init)   // uint64, extended type 9
        return d
    }

    static func asnRecord(_ n: UInt32, _ org: String) -> [UInt8] {
        // Sizes 29 to 31 are escapes in the format: a 30-byte string is "29 + 1".
        func str(_ s: String) -> [UInt8] { (s.utf8.count < 29 ? [UInt8(0x40 | s.utf8.count)] : [0x40 | 29, UInt8(s.utf8.count - 29)]) + Array(s.utf8) }
        return [0xe2] + str("autonomous_system_number") + [0xc4] + withUnsafeBytes(of: n.bigEndian, Array.init)
            + str("autonomous_system_organization") + str(org)
    }

    func testTinyASNDatabase() throws {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("rat-asn-\(UUID()).mmdb")
        try Self.tinyDatabase(record: Self.asnRecord(13335, "Cloudflare, Inc.")).write(to: url)
        defer { try? FileManager.default.removeItem(at: url) }
        let db = try ASNDatabase(path: url.path)
        XCTAssertEqual(db.owner("1.1.1.1"), NetworkOwner(number: 13335, organization: "Cloudflare, Inc."))
        XCTAssertEqual(db.owner("1.1.1.1")?.label, "AS13335 Cloudflare, Inc.")
        XCTAssertNil(db.owner("2606:4700::1111"), "an IPv4 database has no IPv6 records")
        XCTAssertEqual(db.db.databaseType, "Test-ASN")
        XCTAssertEqual(db.db.buildDate, Date(timeIntervalSince1970: 1_790_000_000))
    }

    func testMalformedFilesAreRejectedOrReturnNothing() throws {
        let good = Self.tinyDatabase(record: Self.asnRecord(1, "x"))
        // Truncated anywhere: never a crash, either an error at open or no answer.
        for cut in stride(from: 0, to: good.count, by: 3) {
            let d = good.prefix(cut) + good.suffix(from: good.count - min(good.count - cut, 0))
            if let db = try? MMDB(data: Data(d)) { _ = db.lookup("1.2.3.4"); _ = db.lookup("::1") }
        }
        // A tree claiming more nodes than the file holds.
        XCTAssertThrowsError(try MMDB(data: Self.tinyDatabase(record: Self.asnRecord(1, "x"), nodeCount: 200).prefix(40) + good.suffix(from: good.count - 80)))
        // Records that are garbage, oversized or point at themselves.
        let bad: [[UInt8]] = [
            [0xff, 0xff, 0xff, 0xff],                 // extended type beyond the spec
            [0x5f, 0xff, 0xff, 0xff],                 // string longer than the file
            [0x9f, 0xff, 0xff, 0xff],                 // bytes longer than the file
            [0xff, 0xff],                             // truncated
            [0x20, 0x00],                             // pointer to itself (a loop)
            [0x08, 0x0b, 0xff, 0xff],                 // array of 65k entries without data
            [0x08, 0x01] + [UInt8](repeating: 0xaa, count: 30),   // int32 with a 30-byte size field is rejected
        ]
        for r in bad {
            let db = try MMDB(data: Self.tinyDatabase(record: r))
            XCTAssertNil(db.lookup("1.2.3.4").flatMap { $0["autonomous_system_number"] }, "\(r.prefix(4))")
        }
        for _ in 0..<200 {
            var noise = [UInt8](repeating: 0, count: Int.random(in: 0...400))
            for i in noise.indices { noise[i] = UInt8.random(in: 0...255) }
            if let db = try? MMDB(data: Self.tinyDatabase(record: noise)) { _ = db.lookup("10.0.0.1") }
            if let db = try? MMDB(data: Data(noise) + Data([0xAB, 0xCD, 0xEF] + Array("MaxMind.com".utf8)) + Data(noise.prefix(40))) { _ = db.lookup("10.0.0.1") }
        }
    }

    /// The bundled DB-IP ASN file, when present (RAT_GEOIP_ASN_DB).
    func testBundledASNDatabase() throws {
        guard let p = ProcessInfo.processInfo.environment["RAT_GEOIP_ASN_DB"] else { throw XCTSkip("RAT_GEOIP_ASN_DB not set") }
        let db = try ASNDatabase(path: p)
        XCTAssertEqual(db.owner("1.1.1.1")?.number, 13335)
        XCTAssertEqual(db.owner("8.8.8.8")?.number, 15169)
        XCTAssertNotNil(db.owner("2606:4700:4700::1111"))
        XCTAssertNil(db.owner("192.168.1.1"))
        XCTAssertTrue(db.db.databaseType.contains("ASN"), db.db.databaseType)
    }
}
