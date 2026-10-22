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
