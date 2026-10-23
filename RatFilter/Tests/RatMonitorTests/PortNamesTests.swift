import XCTest
@testable import RatMonitor

final class PortNamesTests: XCTestCase {
    func testWellKnownPorts() {
        XCTAssertEqual(PortNames.name(port: 443, proto: .tcp), "HTTPS")
        XCTAssertEqual(PortNames.name(port: 443, proto: .udp), "QUIC", "UDP 443 is HTTP/3, not HTTPS")
        XCTAssertEqual(PortNames.name(port: 853, proto: .tcp), "DoT")
        XCTAssertEqual(PortNames.name(port: 853, proto: .udp), "DoQ")
        XCTAssertEqual(PortNames.name(port: 5223, proto: .tcp), "APN")
        XCTAssertEqual(PortNames.name(port: 53, proto: .udp), "DNS")
        XCTAssertEqual(PortNames.name(port: 2484, proto: .tcp), "Oracle-TLS")
        XCTAssertNil(PortNames.name(port: 49152, proto: .tcp))
        XCTAssertNil(PortNames.name(port: 0, proto: .tcp))
    }

    func testTableIsSane() {
        XCTAssertGreaterThan(PortNames.common.count, 270)
        for (p, n) in PortNames.common {
            XCTAssertTrue((1...65535).contains(p), "\(p)")
            XCTAssertFalse(n.isEmpty || n.count > 16 || n.contains(" "), "\(p) \(n)")
        }
    }
}
