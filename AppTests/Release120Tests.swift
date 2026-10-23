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
}
