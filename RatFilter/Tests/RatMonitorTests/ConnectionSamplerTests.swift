import XCTest
import Darwin
@testable import RatMonitor

final class ConnectionSamplerTests: XCTestCase {
    /// Open a real loopback TCP connection from this process and check the sampler sees it.
    func testSeesOwnLoopbackConnection() throws {
        let server = socket(AF_INET, SOCK_STREAM, 0)
        var addr = sockaddr_in(sin_len: UInt8(MemoryLayout<sockaddr_in>.size), sin_family: sa_family_t(AF_INET),
                               sin_port: 0, sin_addr: in_addr(s_addr: inet_addr("127.0.0.1")), sin_zero: (0,0,0,0,0,0,0,0))
        var len = socklen_t(MemoryLayout<sockaddr_in>.size)
        withUnsafePointer(to: &addr) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { _ = Darwin.bind(server, $0, len) } }
        listen(server, 1)
        withUnsafeMutablePointer(to: &addr) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { _ = getsockname(server, $0, &len) } }
        let port = Int(UInt16(bigEndian: addr.sin_port))

        let client = socket(AF_INET, SOCK_STREAM, 0)
        let rc = withUnsafePointer(to: &addr) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { connect(client, $0, len) } }
        XCTAssertEqual(rc, 0)
        defer { close(client); close(server) }

        let mine = ConnectionSampler.sample().filter { $0.pid == getpid() }
        let hit = mine.first { $0.proto == .tcp && $0.remoteAddress == "127.0.0.1" && $0.remotePort == port && $0.tcpState == "ESTABLISHED" }
        XCTAssertNotNil(hit, "expected loopback connection to port \(port); saw \(mine)")
        XCTAssertTrue(mine.contains { $0.tcpState == "LISTEN" && $0.localPort == port })
    }

    func testSampleReportsOtherProcesses() {
        let pids = Set(ConnectionSampler.sample().map(\.pid))
        XCTAssertTrue(pids.count >= 1)
    }
}
