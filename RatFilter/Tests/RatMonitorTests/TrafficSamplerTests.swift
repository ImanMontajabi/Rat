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

    func testParsesConnectionsUnderTheirProcess() {
        let csv = """
        ,bytes_in,bytes_out,
        apsd.388,5233,16483,
        tcp4 192.168.178.39:50576<->17.57.146.22:5223,5233,16483,
        udp4 *:56280<->*:*,0,2230,
        Google Chrome He.812,900,80,
        tcp6 2001:db8::1.50972<->2606:4700:4700::1111.443,700,60,
        udp6 fe80::1%en0.5353<->ff02::fb.5353,200,20,
        tcp4 127.0.0.1:8021<->*:*,,,
        """
        let s = TrafficSampler.parseSample(csv)
        XCTAssertEqual(s.processes.map(\.pid), [388, 812])
        XCTAssertEqual(s.flows, [
            FlowCounter(pid: 388, proto: .tcp, localPort: 50576, remoteAddress: "17.57.146.22", remotePort: 5223, bytesIn: 5233, bytesOut: 16483),
            FlowCounter(pid: 812, proto: .tcp, localPort: 50972, remoteAddress: "2606:4700:4700::1111", remotePort: 443, bytesIn: 700, bytesOut: 60),
            FlowCounter(pid: 812, proto: .udp, localPort: 5353, remoteAddress: "ff02::fb", remotePort: 5353, bytesIn: 200, bytesOut: 20),
        ])
        XCTAssertEqual(s.flows[1].key, FlowCounter.key(pid: 812, proto: .tcp, localPort: 50972, remotePort: 443))
        // The -P form (processes only) still parses the same way.
        XCTAssertEqual(TrafficSampler.parse(csv).map(\.name), ["apsd", "Google Chrome He"])
    }

    func testLiveSampleWithFlows() {
        let s = TrafficSampler.sampleWithFlows()
        XCTAssertFalse(s.processes.isEmpty)
        XCTAssertTrue(s.flows.allSatisfy { s.processes.map(\.pid).contains($0.pid) })
    }

    func testLiveSampleReturnsRows() {
        XCTAssertFalse(TrafficSampler.sample().isEmpty)
    }
}
