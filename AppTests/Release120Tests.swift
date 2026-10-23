import XCTest
import RatFilterCore
import RatMonitor
import RatEnforce
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
}
