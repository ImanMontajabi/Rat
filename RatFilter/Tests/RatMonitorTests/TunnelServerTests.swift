import XCTest
@testable import RatMonitor

/// Where a VPN tunnel leads (#45): the servers its client (or the client's loopback relay) carries it to, and their
/// one country. Rat and the helper both use these functions.
final class TunnelServerTests: XCTestCase {
    let tunnels = ["100.127.80.66": "utun420"]
    private func isLocal(_ a: String) -> Bool { a.hasPrefix("192.168.") || a.hasPrefix("10.") }

    private func c(_ remote: String, _ port: Int, _ proto: ObservedConnection.Proto = .udp, local: String = "192.168.178.39", state: String? = nil,
                   localPort: Int = 50000) -> ObservedConnection {
        ObservedConnection(pid: 1, processPath: "/Library/Application Support/Windscribe/bin/wireguard", proto: proto, remoteAddress: remote,
                           remotePort: port, localPort: localPort, tcpState: state, localAddress: local)
    }

    func testTheClientsOutsideConnectionsAreTheCarriers() {
        let owner = [c("185.1.2.3", 443), c("185.1.2.3", 443, localPort: 50001),
                     c("104.20.1.1", 443, .tcp, state: "ESTABLISHED"),          // its API, over TCP
                     c("100.64.0.1", 53, local: "100.127.80.66"),                // through its own tunnel
                     c("192.168.178.1", 53),                                     // the router
                     c("127.0.0.1", 9000, .tcp, state: "ESTABLISHED"),           // loopback
                     c("", 0)]                                                   // unconnected
        XCTAssertEqual(NetworkRoutes.carrierServers(owner: owner, relays: [], tunnels: tunnels, isLocal: isLocal), ["185.1.2.3"], "UDP first, one address once")
        XCTAssertEqual(NetworkRoutes.carrierServers(owner: [c("104.20.1.1", 443, .tcp, state: "ESTABLISHED")], relays: [], tunnels: tunnels, isLocal: isLocal),
                       ["104.20.1.1"], "OpenVPN over TCP: the TCP ones then")
        XCTAssertEqual(NetworkRoutes.carrierServers(owner: [c("10.0.0.5", 1194)], relays: [], tunnels: tunnels, isLocal: isLocal), [], "a server in the LAN is none")
    }

    func testARelaysConnectionsCountWhenTheClientHasNone() {
        // Stealth mode: the client talks to a relay on loopback, the relay to the server over TCP 443.
        let owner = [c("127.0.0.1", 1194, .tcp, local: "127.0.0.1", state: "ESTABLISHED")]
        let relay = [c("212.5.6.7", 443, .tcp, state: "ESTABLISHED"), c("", 0, .tcp, local: "127.0.0.1", state: "LISTEN", localPort: 1194)]
        XCTAssertEqual(NetworkRoutes.relayPorts(of: owner), [1194])
        XCTAssertEqual(NetworkRoutes.carrierServers(owner: owner, relays: relay, tunnels: tunnels, isLocal: isLocal), ["212.5.6.7"])
        XCTAssertEqual(NetworkRoutes.carrierServers(owner: [c("185.1.2.3", 443)], relays: relay, tunnels: tunnels, isLocal: isLocal), ["185.1.2.3"],
                       "the client's own come first")
    }

    func testAWireGuardClientsServerIsTheRouteItPins() {
        // WireGuard (Windscribe's amneziawg) sends from one unconnected UDP socket: no server in its sockets, only the
        // route that keeps the server outside the tunnel.
        let owner = [c("", 0, localPort: 54318), c("104.20.1.1", 443, .tcp, state: "CLOSED", localPort: 0)].filter { $0.remotePort == 0 }
        XCTAssertEqual(NetworkRoutes.carrierServers(owner: owner, relays: [], tunnels: tunnels, isLocal: isLocal, pinned: { ["185.238.28.49", "185.238.28.49"] }),
                       ["185.238.28.49"])
        XCTAssertEqual(NetworkRoutes.carrierServers(owner: owner + [c("185.1.2.3", 443)], relays: [], tunnels: tunnels, isLocal: isLocal, pinned: { ["185.238.28.49"] }),
                       ["185.1.2.3"], "a connected carrier comes first")
        XCTAssertEqual(NetworkRoutes.carrierServers(owner: [c("", 0, local: "127.0.0.1", localPort: 9000)], relays: [], tunnels: tunnels, isLocal: isLocal,
                                                    pinned: { ["185.238.28.49"] }), [], "a socket on loopback carries nothing out")
        XCTAssertEqual(NetworkRoutes.carrierServers(owner: [c("104.20.1.1", 443, .tcp, state: "LISTEN")], relays: [], tunnels: tunnels, isLocal: isLocal,
                                                    pinned: { ["185.238.28.49"] }), [], "no UDP socket: no pinned route")
        XCTAssertEqual(NetworkRoutes.carrierServers(owner: owner, relays: [], tunnels: tunnels, isLocal: isLocal, pinned: { ["192.168.178.1", "127.0.0.1"] }), [])
    }

    func testPinnedRoutesBelongOnlyToTheTunnelCarryingTheInternet() {
        let routes = [NetworkRoutes.HostRoute(destination: "185.238.28.49", interface: "en0"),
                      NetworkRoutes.HostRoute(destination: "10.0.0.9", interface: "en0"),          // the LAN
                      NetworkRoutes.HostRoute(destination: "100.64.0.9", interface: "utun420"),    // into the tunnel
                      NetworkRoutes.HostRoute(destination: "127.0.0.2", interface: "lo0"),
                      NetworkRoutes.HostRoute(destination: "fe80::1", interface: "en0")]
        XCTAssertEqual(NetworkRoutes.pinnedServers(for: "utun420", isLocal: isLocal, routes: { routes }, internet: { "utun420" }), ["185.238.28.49"])
        XCTAssertEqual(NetworkRoutes.pinnedServers(for: "utun420", isLocal: isLocal, routes: { routes }, internet: { "utun3" }), [], "another tunnel takes the Internet")
        XCTAssertEqual(NetworkRoutes.pinnedServers(for: "utun420", isLocal: isLocal, routes: { routes }, internet: { nil }), [], "a split tunnel")
    }

    func testTheRoutingTableIsRead() {
        // Every Mac has no pinned route of its own; whatever a VPN pinned is a gateway route to one host.
        for r in NetworkRoutes.hostRoutes() { XCTAssertFalse(r.destination.isEmpty); XCTAssertFalse(r.interface.isEmpty) }
    }

    func testOneCountryOrNone() {
        let places = ["185.1.2.3": "DE", "185.1.2.4": "DE", "212.5.6.7": "NL"]
        XCTAssertEqual(NetworkRoutes.serverCountry(["185.1.2.3", "185.1.2.4"], lookup: { places[$0] }), "DE")
        XCTAssertNil(NetworkRoutes.serverCountry(["185.1.2.3", "212.5.6.7"], lookup: { places[$0] }), "two countries: not known")
        XCTAssertNil(NetworkRoutes.serverCountry(["185.1.2.3", "9.9.9.9"], lookup: { places[$0] }), "one not placed")
        XCTAssertNil(NetworkRoutes.serverCountry([], lookup: { places[$0] }), "no carrier")
    }

    func testTheTunnelASocketGoesThrough() {
        func iface(_ local: String, _ remote: String, route: String? = nil) -> String? {
            NetworkRoutes.tunnelInterface(localAddress: local, remoteAddress: remote, tunnels: tunnels, isLocal: isLocal, route: { _ in route })
        }
        XCTAssertEqual(iface("100.127.80.66", "203.0.113.5"), "utun420", "bound to the tunnel's address")
        XCTAssertNil(iface("192.168.178.39", "203.0.113.5", route: "utun420"), "bound to Wi-Fi: outside, whatever the routes say")
        XCTAssertEqual(iface("0.0.0.0", "203.0.113.5", route: "utun420"), "utun420", "no address of its own: the routing table")
        XCTAssertNil(iface("0.0.0.0", "203.0.113.5", route: "en0"))
        XCTAssertNil(iface("100.127.80.66", "192.168.178.1"), "the local network")
        XCTAssertNil(iface("127.0.0.1", "203.0.113.5", route: "utun420"), "loopback")
        XCTAssertEqual(iface("", "", route: "utun420"), "utun420", "unconnected: the Internet's route")
        // It agrees with `leavesOutsideTunnel`: a socket goes through a tunnel, or leaves outside, or stays local.
        for (local, remote, route) in [("100.127.80.66", "203.0.113.5", nil), ("192.168.178.39", "203.0.113.5", "utun420"), ("*", "203.0.113.5", "utun420"),
                                       ("*", "203.0.113.5", "en0"), ("100.127.80.66", "10.0.0.1", nil)] as [(String, String, String?)] {
            let outside = NetworkRoutes.leavesOutsideTunnel(localAddress: local, remoteAddress: remote, tunnels: tunnels, isLocal: isLocal, route: { _ in route })
            XCTAssertFalse(outside && iface(local, remote, route: route) != nil, "\(local) → \(remote)")
        }
    }

    func testOwnersScanDoesNotFail() {
        // No assertion on what is found: whatever VPN this Mac has up. The owners' paths agree with `tunnelOwners`.
        let procs = NetworkRoutes.tunnelOwnerProcesses(relays: true)
        XCTAssertEqual(procs.mapValues(\.path), NetworkRoutes.tunnelOwners())
    }
}
