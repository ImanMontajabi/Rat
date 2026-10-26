import XCTest
import RatMonitor
@testable import Rat

/// VPN tags on every level: a socket bound to the tunnel's address, or (without an address of its own) one whose
/// server the routing table sends through the tunnel, is tagged; the VPN client's own connection is the tunnel's
/// carrier; app and process rows sum up their connections' tags. The live test runs on a Mac whose VPN is on.
@MainActor
final class VPNRouteTests: XCTestCase {
    private let client = "/Library/Application Support/Windscribe/bin/windscribeamneziawg"

    private func marker() -> RouteMarker {
        let m = RouteMarker()
        m.set(tunnelAddresses: ["100.127.80.66": "utun420"], tunnelNames: ["utun420": "Windscribe"], proxies: [],
              tunnelClients: [client: "Windscribe"], routes: ["203.0.113.8": "utun420", "198.51.100.3": "en0"])
        return m
    }

    func testSocketAddressThenRoutingTable() {
        let m = marker()
        let vpn = RouteTag.vpn(name: "Windscribe", interface: "utun420")
        XCTAssertEqual(m.route(localAddress: "100.127.80.66", remoteAddress: "142.251.20.113", remotePort: 443), vpn, "bound to the tunnel")
        XCTAssertNil(m.route(localAddress: "192.168.178.39", remoteAddress: "203.0.113.8", remotePort: 443), "opened on Wi-Fi before the VPN came up: still on Wi-Fi")
        XCTAssertEqual(m.route(localAddress: "*", remoteAddress: "203.0.113.8", remotePort: 443), vpn, "no address of its own: the routing table decides")
        XCTAssertEqual(m.route(localAddress: "0.0.0.0", remoteAddress: "203.0.113.8", remotePort: 443), vpn)
        XCTAssertNil(m.route(localAddress: "*", remoteAddress: "198.51.100.3", remotePort: 443), "routed outside the tunnel")
        XCTAssertNil(m.route(localAddress: "*", remoteAddress: "127.0.0.1", remotePort: 8080), "loopback never goes through a VPN")
        XCTAssertNil(m.route(localAddress: "*", remoteAddress: "fe80::1", remotePort: 5353), "nor link-local")
    }

    func testTheClientsOwnConnectionIsTheCarrier() {
        let m = marker()
        let carrier = m.route(localAddress: "192.168.178.39", remoteAddress: "185.104.184.151", remotePort: 443, processPath: client)
        XCTAssertEqual(carrier, .vpnServer(name: "Windscribe"))
        XCTAssertEqual(carrier?.badge, "VPN server · Windscribe")
        XCTAssertFalse(carrier?.isVPN ?? true, "it carries the tunnel, it does not go through it")
        XCTAssertFalse(carrier?.isProxy ?? true)
        let r = RemoteHost(address: "185.104.184.151", host: "185.104.184.151", port: 443, proto: "UDP", route: carrier)
        XCTAssertFalse(RouteFilter.vpn.matches(r)); XCTAssertFalse(RouteFilter.proxy.matches(r))
        XCTAssertEqual(m.route(localAddress: "100.127.80.66", remoteAddress: "104.20.1.154", remotePort: 443, processPath: client), .vpn(name: "Windscribe", interface: "utun420"),
                       "the client's own traffic inside the tunnel is VPN traffic")
    }

    func testRowsSumUpTheirConnectionsTags() {
        func host(_ a: String, _ route: RouteTag? = nil, via: ProxyHop? = nil) -> RemoteHost {
            RemoteHost(address: a, host: a, port: 443, proto: "TCP", via: via, route: route)
        }
        let vpn = RouteTag.vpn(name: "Windscribe", interface: "utun420")
        let ssh = ProxyHop(kind: "SOCKS5", process: "ssh", listener: "127.0.0.1:1080")
        let items = RouteSummaryBadges.items([host("203.0.113.1", vpn), host("203.0.113.2", vpn), host("203.0.113.3"), host("example.org", via: ssh),
                                              host("185.104.184.151", .vpnServer(name: "Windscribe"))])
        XCTAssertEqual(items.map(\.text), ["VPN · Windscribe", "Proxy · ssh", "VPN server · Windscribe"], "each tag once, VPNs first")
        XCTAssertEqual(RouteSummaryBadges.items([host("203.0.113.3")]), [], "a row without tunnelled or proxied connections has no tag")
    }

    func testDemoRowsShowTags() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("rat-vpnrows-\(UUID())")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let l = Ledger(directory: dir, helperInstalled: false, names: HostNames(resolve: { _ in nil }))
        l.installDemoData()
        let telegram = try XCTUnwrap(l.apps.first { $0.identity.name == "Telegram" })
        XCTAssertEqual(RouteSummaryBadges.items(telegram.remotes).map(\.text), ["VPN · Windscribe"], "the app row")
        let firefox = try XCTUnwrap(l.apps.first { $0.identity.name == "Firefox" })
        XCTAssertEqual(RouteSummaryBadges.items(firefox.remotes).map(\.text), ["Proxy · Tor", "Proxy · ssh"])
    }

    // MARK: live

    /// With a VPN carrying the Internet: the route marker finds its tunnel, names it after the client the root
    /// helper (or this user) sees holding it, and the ledger tags this Mac's real connections.
    func testLiveVPNTagsRealConnections() async throws {
        guard let tunnel = NetworkRoutes.internetTunnel() else { throw XCTSkip("no VPN carries the Internet on this Mac") }
        let helperTunnels = (try? Data(contentsOf: URL(fileURLWithPath: Enforcer.statusPath)))
            .flatMap { try? JSONSerialization.jsonObject(with: $0) as? [String: Any] }?["tunnels"] as? [String: String]
        let m = RouteMarker()
        m.refresh(helperTunnels: helperTunnels)
        XCTAssertEqual(m.internetTunnel, tunnel)
        let owner = (helperTunnels ?? [:]).merging(NetworkRoutes.tunnelOwners()) { a, _ in a }[tunnel]
        let expected = RouteMarker.name(interface: tunnel, service: NetworkRoutes.vpnServiceNames()[tunnel], owner: owner)
        XCTAssertEqual(m.tunnelNames[tunnel], expected)
        if let owner, let known = NetworkRoutes.knownApp(inPath: owner) {
            XCTAssertEqual(m.tunnelNames[tunnel], known, "named after its client (\(owner))")
        }

        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("rat-livevpn-\(UUID())")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let l = Ledger(directory: dir, helperInstalled: false, names: HostNames(resolve: { _ in nil }))
        let conns = ConnectionSampler.sample()
        await l.ingest(conns, [])
        let onTunnel = conns.filter { m.tunnelAddresses[$0.localAddress] == tunnel && $0.tcpState == "ESTABLISHED" }
        try XCTSkipIf(onTunnel.isEmpty, "no open connection of this user through \(tunnel) right now")
        let tagged = l.apps.flatMap(\.remotes).filter { $0.route?.isVPN ?? false }
        XCTAssertFalse(tagged.isEmpty, "connections through \(tunnel) are tagged")
        XCTAssertTrue(tagged.allSatisfy { if case let .vpn(_, i) = $0.route { return i == tunnel }; return false })
        XCTAssertFalse(l.apps.filter { !RouteSummaryBadges.items($0.remotes).isEmpty }.isEmpty, "and their apps' rows show it")
    }
}
