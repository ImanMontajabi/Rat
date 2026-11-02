import XCTest
import RatMonitor
@testable import Rat

/// The header's rate, the session's totals and the chart count the Mac's traffic once, as the line carried it; each
/// app keeps the traffic of its own sockets.
@MainActor
final class NetworkRateTests: XCTestCase {
    private func ledger() throws -> Ledger {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("rat-rate-\(UUID())")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        addTeardownBlock { try? FileManager.default.removeItem(at: dir) }
        return Ledger(directory: dir, helperInstalled: false, names: HostNames(resolve: { _ in nil }))
    }

    private let browser = "/Applications/Browser.app/Contents/MacOS/Browser"
    private let vpn = "/Applications/Tunnel.app/Contents/MacOS/Tunnel"
    private let proxy = "/Applications/Proxy.app/Contents/MacOS/Proxy"

    private func conns() -> [ObservedConnection] {
        [ObservedConnection(pid: 5, processPath: browser, proto: .tcp, remoteAddress: "203.0.113.1", remotePort: 443, localPort: 50000, tcpState: "ESTABLISHED"),
         ObservedConnection(pid: 6, processPath: vpn, proto: .udp, remoteAddress: "198.51.100.7", remotePort: 51820, localPort: 50001, tcpState: ""),
         ObservedConnection(pid: 7, processPath: proxy, proto: .tcp, remoteAddress: "192.0.2.9", remotePort: 443, localPort: 50002, tcpState: "ESTABLISHED")]
    }

    private func link(en0: UInt64, en0Out: UInt64, loopback: UInt64, tunnel: UInt64) -> LinkSample {
        LinkSample(counters: [InterfaceCounter(name: "en0", bytesIn: en0, bytesOut: en0Out), InterfaceCounter(name: "lo0", bytesIn: loopback, bytesOut: loopback),
                              InterfaceCounter(name: "utun4", bytesIn: tunnel, bytesOut: tunnel / 100)],
                   internet: ["en0"])
    }

    /// A 6 MB/s download through a VPN and a local proxy: the app's socket, the proxy's loopback copy of it and the
    /// VPN client's carrier each count it, so a sum over processes said 24 MB/s down and 6 MB/s up.
    func testTheTotalCountsALineByteOnceThroughAVPNAndALocalProxy() async throws {
        let l = try ledger()
        let t0 = Date()
        let start: [TrafficCounter] = [TrafficCounter(pid: 5, name: "Browser", bytesIn: 0, bytesOut: 0), TrafficCounter(pid: 6, name: "Tunnel", bytesIn: 0, bytesOut: 0),
                                       TrafficCounter(pid: 7, name: "Proxy", bytesIn: 0, bytesOut: 0)]
        await l.ingest(conns(), start, link: link(en0: 1_000, en0Out: 100, loopback: 0, tunnel: 0), now: t0)
        XCTAssertEqual(l.rateIn, 0, "the first sample is the baseline"); XCTAssertEqual(l.sessionIn, 0)

        let mb9: UInt64 = 9_000_000
        let moved: [TrafficCounter] = [TrafficCounter(pid: 5, name: "Browser", bytesIn: mb9, bytesOut: 90_000),
                                       TrafficCounter(pid: 6, name: "Tunnel", bytesIn: mb9, bytesOut: 90_000),
                                       TrafficCounter(pid: 7, name: "Proxy", bytesIn: mb9, bytesOut: mb9)]   // its loopback socket sends what it got
        await l.ingest(conns(), moved, link: link(en0: 1_000 + mb9, en0Out: 100 + 90_000, loopback: mb9, tunnel: mb9), now: t0 + 1.5)
        XCTAssertEqual(l.rateIn, 6_000_000, accuracy: 1, "the line's 6 MB/s, once")
        XCTAssertEqual(l.rateOut, 60_000, accuracy: 1)
        XCTAssertEqual(l.sessionIn, mb9); XCTAssertEqual(l.sessionOut, 90_000)
        XCTAssertEqual(l.history.last?.rx ?? 0, Double(mb9), accuracy: 1, "the chart draws the same bytes")
        // Each row still shows what its own sockets moved.
        let byName = Dictionary(uniqueKeysWithValues: l.apps.map { ($0.identity.name, $0) })
        for name in ["Browser", "Tunnel", "Proxy"] {
            XCTAssertEqual(byName[name]?.rates.last?.rx ?? 0, Double(mb9), accuracy: 1, name)
            XCTAssertEqual(byName[name]?.totalIn, mb9, name)
        }
    }

    /// The rate divides by the time between the two samples, not by a fixed or a shorter window.
    func testTheRateDividesByTheTimeBetweenSamples() async throws {
        let l = try ledger()
        let t0 = Date()
        await l.ingest(conns(), [], link: link(en0: 0, en0Out: 0, loopback: 0, tunnel: 0), now: t0)
        await l.ingest(conns(), [], link: link(en0: 6_000_000, en0Out: 0, loopback: 0, tunnel: 0), now: t0 + 3)
        XCTAssertEqual(l.rateIn, 2_000_000, accuracy: 1, "6 MB in 3 s, though the passes are 1.5 s apart")
        // A pass run right after another (a ✓ cuts the nap short) is not divided by a longer window.
        await l.ingest(conns(), [], link: link(en0: 6_300_000, en0Out: 0, loopback: 0, tunnel: 0), now: t0 + 3.1)
        XCTAssertEqual(l.rateIn, 3_000_000, accuracy: 1)
    }

    /// Traffic that stays on the Mac (between two programs over loopback) is no Internet traffic.
    func testLoopbackTrafficIsNoInternetTraffic() async throws {
        let l = try ledger()
        let t0 = Date()
        let local = [TrafficCounter(pid: 7, name: "Proxy", bytesIn: 0, bytesOut: 0)]
        await l.ingest(conns(), local, link: link(en0: 500, en0Out: 500, loopback: 0, tunnel: 0), now: t0)
        await l.ingest(conns(), [TrafficCounter(pid: 7, name: "Proxy", bytesIn: 40_000_000, bytesOut: 40_000_000)],
                       link: link(en0: 500, en0Out: 500, loopback: 40_000_000, tunnel: 0), now: t0 + 1.5)
        XCTAssertEqual(l.rateIn, 0); XCTAssertEqual(l.rateOut, 0); XCTAssertEqual(l.sessionIn, 0)
        XCTAssertEqual(l.apps.first { $0.identity.name == "Proxy" }?.totalIn, 40_000_000, "the app's own row keeps it")
    }
}
