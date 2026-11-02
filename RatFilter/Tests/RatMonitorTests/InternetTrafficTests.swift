import Darwin
import XCTest
@testable import RatMonitor

final class InternetTrafficTests: XCTestCase {
    /// Counts only what the interfaces leading to the Internet moved since the last sample.
    func testCountsTheGrowthOfInternetInterfacesOnly() {
        var t = InternetTraffic()
        let first = t.update([InterfaceCounter(name: "en0", bytesIn: 1_000, bytesOut: 100), InterfaceCounter(name: "lo0", bytesIn: 9_000, bytesOut: 9_000),
                              InterfaceCounter(name: "utun4", bytesIn: 500, bytesOut: 50)], internet: ["en0"])
        XCTAssertEqual(first.bytesIn, 0, "the first sample is the baseline"); XCTAssertEqual(first.bytesOut, 0)
        // A 6 MB/s download through a VPN for 1.5 s: the tunnel and the Wi-Fi under it both see it; loopback a local proxy's copy.
        let second = t.update([InterfaceCounter(name: "en0", bytesIn: 1_000 + 9_000_000, bytesOut: 100 + 90_000),
                               InterfaceCounter(name: "lo0", bytesIn: 9_000 + 9_000_000, bytesOut: 9_000 + 9_000_000),
                               InterfaceCounter(name: "utun4", bytesIn: 500 + 8_800_000, bytesOut: 50 + 80_000)], internet: ["en0"])
        XCTAssertEqual(second.bytesIn, 9_000_000, "once, as the line carried it"); XCTAssertEqual(second.bytesOut, 90_000)
    }

    func testAnInterfaceThatStartsLeadingToTheInternetCountsAtOnceAndAResetCountsNothing() {
        var t = InternetTraffic()
        _ = t.update([InterfaceCounter(name: "en0", bytesIn: 100, bytesOut: 10), InterfaceCounter(name: "en7", bytesIn: 4_000, bytesOut: 400)], internet: ["en0"])
        // Ethernet gets its default route: its growth since the last sample counts.
        let plugged = t.update([InterfaceCounter(name: "en0", bytesIn: 100, bytesOut: 10), InterfaceCounter(name: "en7", bytesIn: 5_000, bytesOut: 500)], internet: ["en0", "en7"])
        XCTAssertEqual(plugged.bytesIn, 1_000); XCTAssertEqual(plugged.bytesOut, 100)
        // The adapter came back as a new interface: its counters start over, which is no traffic.
        let reset = t.update([InterfaceCounter(name: "en0", bytesIn: 300, bytesOut: 20), InterfaceCounter(name: "en7", bytesIn: 10, bytesOut: 1)], internet: ["en0", "en7"])
        XCTAssertEqual(reset.bytesIn, 200); XCTAssertEqual(reset.bytesOut, 10)
        // An interface seen for the first time is only a baseline.
        let fresh = t.update([InterfaceCounter(name: "en0", bytesIn: 300, bytesOut: 20), InterfaceCounter(name: "en7", bytesIn: 10, bytesOut: 1),
                              InterfaceCounter(name: "en8", bytesIn: 7_000_000_000, bytesOut: 1)], internet: ["en0", "en7", "en8"])
        XCTAssertEqual(fresh.bytesIn, 0)
    }

    func testInternetInterfacesLeaveOutLoopbackAndTunnels() {
        // macOS's own utun0-3 hold scoped IPv6 defaults; a full-tunnel VPN may add one on its tunnel.
        XCTAssertEqual(InternetTraffic.internetInterfaces(defaultRoutes: ["en0", "utun0", "utun1", "utun4", "lo0"]), ["en0"])
        XCTAssertEqual(InternetTraffic.internetInterfaces(defaultRoutes: ["en0", "en7", "ipsec0", "ppp0"]), ["en0", "en7"], "Wi-Fi and Ethernet both; an L2TP VPN's ppp0 runs over them")
        XCTAssertEqual(InternetTraffic.internetInterfaces(defaultRoutes: ["ppp0", "utun3"]), ["ppp0"], "PPPoE: the line itself is PPP")
        XCTAssertEqual(InternetTraffic.internetInterfaces(defaultRoutes: ["utun4"]), [], "a tunnel alone is not a line")
        XCTAssertEqual(InternetTraffic.internetInterfaces(defaultRoutes: []), [])
    }

    /// Routing messages as `NET_RT_DUMP` returns them: a default route, a VPN's 0/1, a pinned host route, an IPv6 default.
    func testReadsDefaultRoutesFromARouteDump() {
        func message(index: UInt16, flags: Int32, addrs: Int32, _ sockaddrs: [[UInt8]]) -> [UInt8] {
            func padded(_ s: [UInt8]) -> [UInt8] { s.isEmpty ? [0, 0, 0, 0] : s + [UInt8](repeating: 0, count: (4 - s.count % 4) % 4) }
            let body = sockaddrs.flatMap(padded)
            var m = rt_msghdr()
            m.rtm_msglen = UInt16(MemoryLayout<rt_msghdr>.size + body.count); m.rtm_version = UInt8(RTM_VERSION); m.rtm_type = UInt8(RTM_GET)
            m.rtm_index = index; m.rtm_flags = flags; m.rtm_addrs = addrs
            return withUnsafeBytes(of: m) { Array($0) } + body
        }
        func sin(_ a: [UInt8]) -> [UInt8] { [16, UInt8(AF_INET), 0, 0] + a + [UInt8](repeating: 0, count: 8) }
        func sin6(_ a: [UInt8]) -> [UInt8] { [28, UInt8(AF_INET6)] + [UInt8](repeating: 0, count: 6) + a + [UInt8](repeating: 0, count: 16 - a.count) + [0, 0, 0, 0] }
        let gw = RTF_UP | RTF_GATEWAY | RTF_STATIC
        let all = RTA_DST | RTA_GATEWAY | RTA_NETMASK
        let dump = message(index: 5, flags: gw, addrs: all, [sin([0, 0, 0, 0]), sin([192, 168, 1, 1]), []])   // default 192.168.1.1 en0
            + message(index: 9, flags: gw, addrs: all, [sin([0, 0, 0, 0]), sin([10, 0, 0, 1]), [5, 0, 0, 0, 0x80]])   // 0/1 → utun
            + message(index: 6, flags: gw | RTF_HOST, addrs: RTA_DST | RTA_GATEWAY, [sin([185, 238, 28, 49]), sin([192, 168, 1, 1])])   // pinned server
            + message(index: 7, flags: RTF_UP, addrs: all, [sin([0, 0, 0, 0]), sin([0, 0, 0, 0]), []])   // no gateway
            + message(index: 8, flags: gw | RTF_IFSCOPE, addrs: all, [sin6([]), sin6([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]), []])   // scoped ::/0
        XCTAssertEqual(InternetTraffic.defaultRouteIndices(in: dump), [5, 8])
        XCTAssertEqual(InternetTraffic.defaultRouteIndices(in: Array(dump.prefix(50))), [], "a cut-off buffer reads nothing")
    }

    /// The kernel's counters and routes on this Mac.
    func testLiveCountersAndDefaultRoutes() throws {
        let counters = InternetTraffic.counters()
        XCTAssertTrue(counters.contains { $0.name == "lo0" }, "every interface is listed")
        let defaults = InternetTraffic.defaultRouteInterfaces()
        let internet = InternetTraffic.internetInterfaces(defaultRoutes: defaults)
        XCTAssertFalse(internet.contains("lo0"))
        XCTAssertFalse(internet.contains(where: NetworkRoutes.isTunnel))
        guard let route = NetworkRoutes.routeInterface(to: "1.1.1.1") else { throw XCTSkip("no route to the Internet") }
        if !NetworkRoutes.isTunnel(route) { XCTAssertTrue(internet.contains(route), "the interface the Internet goes through: \(route), defaults \(defaults)") }
        else { XCTAssertFalse(internet.isEmpty, "a VPN's tunnel runs over a line: defaults \(defaults)") }
        XCTAssertTrue(internet.allSatisfy { name in counters.contains { $0.name == name } })
    }
}
