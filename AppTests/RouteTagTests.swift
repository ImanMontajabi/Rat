import XCTest
import RatMonitor
@testable import Rat

/// VPN and proxy tags (1.3.0): structured route tags, local proxies tagged without the helper, and the vpn / proxy
/// filter words of the search field.
@MainActor
final class RouteTagTests: XCTestCase {
    func testBadgesAndLabels() {
        let vpn = RouteTag.vpn(name: "Windscribe", interface: "utun3")
        XCTAssertEqual(vpn.badge, "VPN · Windscribe · utun3")
        XCTAssertEqual(vpn.shortBadge, "VPN · Windscribe")
        XCTAssertEqual(vpn.label, "via VPN (Windscribe)", "alerts keep the 1.2.0 wording")
        XCTAssertEqual(RouteTag.vpn(name: "utun4", interface: "utun4").badge, "VPN · utun4", "an unnamed tunnel shows its interface once")
        XCTAssertEqual(RouteTag.systemProxy(kind: "HTTPS", host: "proxy.example", port: 3128).badge, "Proxy · System HTTPS")
        XCTAssertEqual(RouteTag.localProxy(program: "ssh", listener: "127.0.0.1:1080").badge, "Proxy · ssh")
        XCTAssertTrue(vpn.isVPN); XCTAssertFalse(vpn.isProxy)
        XCTAssertTrue(RouteTag.localProxy(program: "Tor", listener: "127.0.0.1:9050").isProxy)
    }

    func testLocalProxyNeedsAnotherProgramsProxyListener() {
        let ssh = (pid: Int32(50), path: "/usr/bin/ssh")
        XCTAssertEqual(RouteMarker.localProxy(remoteAddress: "127.0.0.1", remotePort: 1080, pid: 60, listener: ssh), .localProxy(program: "ssh", listener: "127.0.0.1:1080"))
        XCTAssertEqual(RouteMarker.localProxy(remoteAddress: "::1", remotePort: 1080, pid: 60, listener: ssh), .localProxy(program: "ssh", listener: "[::1]:1080"))
        XCTAssertNil(RouteMarker.localProxy(remoteAddress: "127.0.0.1", remotePort: 1080, pid: 50, listener: ssh), "a process talking to itself")
        XCTAssertNil(RouteMarker.localProxy(remoteAddress: "127.0.0.1", remotePort: 3000, pid: 60, listener: (70, "/usr/local/bin/node")), "not a proxy")
        XCTAssertNil(RouteMarker.localProxy(remoteAddress: "203.0.113.1", remotePort: 1080, pid: 60, listener: ssh), "not loopback")
        XCTAssertNil(RouteMarker.localProxy(remoteAddress: "127.0.0.1", remotePort: 1080, pid: 60, listener: nil), "nobody listens")
    }

    func testLedgerTagsConnectionsToALocalProxy() async throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("rat-route-\(UUID())")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let ledger = Ledger(directory: dir, helperInstalled: false)
        let client = "/Applications/Demo/Foo.app/Contents/MacOS/Foo"
        await ledger.ingest([
            ObservedConnection(pid: 50, processPath: "/usr/bin/ssh", proto: .tcp, remoteAddress: "", remotePort: 0, localPort: 1080, tcpState: "LISTEN"),
            ObservedConnection(pid: 60, processPath: client, proto: .tcp, remoteAddress: "127.0.0.1", remotePort: 1080, localPort: 51000, tcpState: "ESTABLISHED"),
            ObservedConnection(pid: 60, processPath: client, proto: .tcp, remoteAddress: "203.0.113.9", remotePort: 443, localPort: 51001, tcpState: "ESTABLISHED"),
        ], [])
        let foo = try XCTUnwrap(ledger.apps.first { $0.id == "/Applications/Demo/Foo.app" })
        let loop = try XCTUnwrap(foo.remotes.first { $0.address == "127.0.0.1" })
        XCTAssertEqual(loop.route, .localProxy(program: "ssh", listener: "127.0.0.1:1080"))
        XCTAssertTrue(loop.isProxied)
        XCTAssertNil(foo.remotes.first { $0.address == "203.0.113.9" }?.route)
    }

    func testSearchWordsSelectTheRouteFilter() {
        XCTAssertEqual(RouteFilter.parse("vpn", chip: .all).route, .vpn)
        XCTAssertEqual(RouteFilter.parse("VPN", chip: .all).text, "")
        XCTAssertEqual(RouteFilter.parse("is:proxy chrome", chip: .all).route, .proxy)
        XCTAssertEqual(RouteFilter.parse("is:proxy chrome", chip: .all).text, "chrome")
        XCTAssertEqual(RouteFilter.parse("vpn proxy", chip: .all).route, .either)
        XCTAssertEqual(RouteFilter.parse("vpnclient", chip: .all).route, .all, "only whole words")
        XCTAssertEqual(RouteFilter.parse("telegram", chip: .vpn).route, .vpn, "the chip applies without a word")
    }

    func testFilterMatchesTaggedAndUnmaskedConnections() {
        let plain = RemoteHost(address: "203.0.113.1", host: "a.example", port: 443, proto: "TCP")
        var vpn = plain; vpn.route = .vpn(name: "Mullvad", interface: "utun5")
        var unmasked = plain; unmasked.via = ProxyHop(kind: "SOCKS5", process: "ssh", listener: "127.0.0.1:1080")
        var system = plain; system.route = .systemProxy(kind: "HTTP", host: "proxy.example", port: 8080)
        XCTAssertEqual([plain, vpn, unmasked, system].filter(RouteFilter.vpn.matches).count, 1)
        XCTAssertEqual([plain, vpn, unmasked, system].filter(RouteFilter.proxy.matches).count, 2)
        XCTAssertEqual([plain, vpn, unmasked, system].filter(RouteFilter.either.matches).count, 3)
        XCTAssertEqual([plain, vpn, unmasked, system].filter(RouteFilter.all.matches).count, 4)
    }

    func testDemoDataCarriesVPNAndProxyTags() throws {
        let ledger = Ledger(directory: FileManager.default.temporaryDirectory.appendingPathComponent("rat-route-demo-\(UUID())"), helperInstalled: false)
        ledger.installDemoData()
        let all = ledger.apps.flatMap(\.remotes)
        XCTAssertTrue(all.contains { $0.route == .vpn(name: "Windscribe", interface: "utun3") })
        XCTAssertTrue(all.contains { $0.via?.process == "ssh" })
        XCTAssertTrue(all.contains { $0.route == .localProxy(program: "Tor", listener: "127.0.0.1:9050") })
    }
}
