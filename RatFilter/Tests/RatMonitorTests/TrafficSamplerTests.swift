import XCTest
@testable import RatMonitor

final class TrafficSamplerTests: XCTestCase {
    func testParsesNettopCSV() {
        let csv = ",bytes_in,bytes_out,\nmDNSResponder.495,5246963,1927209,\nGoogle Chrome H.1234,10,20,\nbad line\n"
        let rows = TrafficSampler.parse(csv)
        XCTAssertEqual(rows, [
            TrafficCounter(pid: 495, name: "mDNSResponder", bytesIn: 5246963, bytesOut: 1927209),
            TrafficCounter(pid: 1234, name: "Google Chrome H", bytesIn: 10, bytesOut: 20),
        ])
    }

    func testLiveSampleReturnsRows() {
        XCTAssertFalse(TrafficSampler.sample().isEmpty)
    }
}
