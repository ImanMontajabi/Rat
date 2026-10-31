import XCTest
@testable import RatMonitor

final class NetworkRoutesTests: XCTestCase {
    func testTunnelInterfaceNames() {
        for n in ["utun0", "utun12", "ipsec0", "ppp0", "tun3", "tap1", "wg0"] { XCTAssertTrue(NetworkRoutes.isTunnel(n), n) }
        for n in ["en0", "lo0", "utun", "bridge0", "awdl0", "utunx"] { XCTAssertFalse(NetworkRoutes.isTunnel(n), n) }
    }

    func testKnownAppsMatchWholeWordsOnly() {
        XCTAssertEqual(NetworkRoutes.knownApp(inPath: "/Library/SystemExtensions/1A2B/com.windscribe.client.networkextension.systemextension/Contents/MacOS/com.windscribe.client.networkextension"), "Windscribe")
        XCTAssertEqual(NetworkRoutes.knownApp(inPath: "/Applications/NordVPN.app/Contents/MacOS/NordVPN"), "NordVPN")
        XCTAssertEqual(NetworkRoutes.knownApp(inPath: "/Applications/Private Internet Access.app/Contents/MacOS/pia-daemon"), "Private Internet Access")
        XCTAssertEqual(NetworkRoutes.knownApp(inPath: "/Applications/Tor Browser.app/Contents/MacOS/Tor/tor"), "Tor Browser")
        XCTAssertEqual(NetworkRoutes.knownApp(inPath: "/opt/homebrew/bin/tailscaled"), "Tailscale")
        XCTAssertEqual(NetworkRoutes.knownApp(inPath: "/usr/local/bin/sing-box"), "sing-box")
        XCTAssertNil(NetworkRoutes.knownApp(inPath: "/Applications/Activity Monitor.app/Contents/MacOS/Activity Monitor"), "tor inside Monitor")
        XCTAssertNil(NetworkRoutes.knownApp(inPath: "/usr/libexec/spiad"), "pia inside spiad")
        XCTAssertNil(NetworkRoutes.knownApp(inPath: "/Applications/Safari.app/Contents/MacOS/Safari"))
    }

    func testSystemProxySettings() {
        let d: [String: Any] = ["HTTPEnable": 1, "HTTPProxy": "proxy.corp.example", "HTTPPort": 3128,
                                "HTTPSEnable": 0, "HTTPSProxy": "ignored.example", "HTTPSPort": 443,
                                "SOCKSEnable": 1, "SOCKSProxy": "127.0.0.1", "SOCKSPort": 7890,
                                "ProxyAutoConfigEnable": 1]
        let e = NetworkRoutes.proxies(from: d)
        XCTAssertEqual(e, [.init(kind: .http, host: "proxy.corp.example", port: 3128), .init(kind: .socks, host: "127.0.0.1", port: 7890)])
        let addrs = ["proxy.corp.example": Set(["198.51.100.7"])]
        XCTAssertEqual(NetworkRoutes.proxy(for: "198.51.100.7", port: 3128, among: e, addresses: addrs)?.kind, .http)
        XCTAssertNil(NetworkRoutes.proxy(for: "198.51.100.7", port: 443, among: e, addresses: addrs), "same server, other port: not the proxy")
        XCTAssertEqual(NetworkRoutes.proxy(for: "127.0.0.1", port: 7890, among: e, addresses: [:])?.kind, .socks, "a local proxy app (Clash, sing-box)")
        XCTAssertNil(NetworkRoutes.proxy(for: "203.0.113.1", port: 7890, among: e, addresses: [:]))
        XCTAssertEqual(NetworkRoutes.proxies(from: ["HTTPEnable": 1, "HTTPProxy": "", "HTTPPort": 80]), [])
    }

    func testLiveReadsDoNotFail() {
        // The real interface list, this user's kernel control sockets and the System Settings stores.
        _ = NetworkRoutes.tunnelAddresses()
        _ = NetworkRoutes.tunnelOwners()
        _ = NetworkRoutes.vpnServiceNames()
        _ = NetworkRoutes.systemProxies()
        XCTAssertTrue(NetworkRoutes.tunnelAddresses().values.allSatisfy(NetworkRoutes.isTunnel))
    }

    /// The interface `route -n get` prints, for the same addresses.
    private func routeCommand(_ address: String) -> String? {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/sbin/route")
        p.arguments = ["-n", "get", address]
        let out = Pipe(); p.standardOutput = out; p.standardError = FileHandle.nullDevice
        guard (try? p.run()) != nil else { return nil }
        p.waitUntilExit()
        let text = String(decoding: out.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
        return text.split(separator: "\n").first { $0.contains("interface:") }.map { $0.split(separator: ":").last!.trimmingCharacters(in: .whitespaces) }
    }

    func testRouteInterfaceMatchesTheRoutingTable() {
        XCTAssertEqual(NetworkRoutes.routeInterface(to: "127.0.0.1"), "lo0")
        XCTAssertEqual(NetworkRoutes.routeInterface(to: "::1"), "lo0")
        XCTAssertNil(NetworkRoutes.routeInterface(to: "not an address"))
        for a in ["1.1.1.1", "8.8.8.8", "203.0.113.5"] {
            XCTAssertEqual(NetworkRoutes.routeInterface(to: a), routeCommand(a), a)
        }
    }

    /// Live, on a Mac whose VPN carries the Internet (Windscribe, WireGuard, WARP, …): the tunnel is found from the
    /// routing table, it has an address, and this user's connections to the Internet are bound to it.
    func testLiveFullTunnelVPNIsFound() throws {
        guard let tunnel = NetworkRoutes.internetTunnel() else { throw XCTSkip("no VPN carries the Internet on this Mac") }
        XCTAssertTrue(NetworkRoutes.isTunnel(tunnel))
        let addresses = NetworkRoutes.tunnelAddresses().filter { $0.value == tunnel }.map(\.key)
        XCTAssertFalse(addresses.isEmpty, "\(tunnel) carries the Internet, so it has an address")
        let open = ConnectionSampler.sample().filter { $0.proto == .tcp && $0.tcpState == "ESTABLISHED" && !$0.remoteAddress.hasPrefix("127.") && $0.remoteAddress != "::1" && !$0.remoteAddress.hasPrefix("fe80") }
        if !open.isEmpty {
            XCTAssertTrue(open.contains { addresses.contains($0.localAddress) }, "connections go out through \(tunnel): \(Set(open.map(\.localAddress)))")
        }
    }

    func testLocalProxyPrograms() {
        XCTAssertEqual(NetworkRoutes.localProxyProgram(inPath: "/usr/bin/ssh"), "ssh")
        XCTAssertEqual(NetworkRoutes.localProxyProgram(inPath: "/opt/homebrew/bin/tor"), "Tor")
        XCTAssertEqual(NetworkRoutes.localProxyProgram(inPath: "/opt/homebrew/bin/mitmdump"), "mitmproxy")
        XCTAssertEqual(NetworkRoutes.localProxyProgram(inPath: "/Applications/ClashX.app/Contents/MacOS/ClashX"), "ClashX")
        XCTAssertNil(NetworkRoutes.localProxyProgram(inPath: "/usr/local/bin/node"), "a dev server is no proxy")
        XCTAssertNil(NetworkRoutes.localProxyProgram(inPath: "/usr/bin/sshd-keygen-wrapper"))
    }

    /// Whether a socket leaves outside a VPN tunnel ("Only through a VPN", #45).
    func testLeavesOutsideTunnel() {
        let tunnels = ["100.127.80.66": "utun420", "fd00::66": "utun420"]
        let lan: (String) -> Bool = { $0.hasPrefix("192.168.") || $0.hasPrefix("127.") || $0 == "::1" }
        let routes: [String: String] = ["203.0.113.8": "utun420", "198.51.100.3": "en0", "": "utun420"]
        func off(_ local: String, _ remote: String, tunnels: [String: String] = tunnels, routes: [String: String] = routes) -> Bool {
            NetworkRoutes.leavesOutsideTunnel(localAddress: local, remoteAddress: remote, tunnels: tunnels, isLocal: lan) { routes[$0 ?? ""] }
        }
        XCTAssertFalse(off("100.127.80.66", "142.251.20.113"), "bound to the tunnel")
        XCTAssertFalse(off("fd00::66", "2001:db8::1"))
        XCTAssertTrue(off("192.168.178.39", "203.0.113.8"), "opened on Wi-Fi before the VPN: stays on Wi-Fi")
        XCTAssertFalse(off("", "203.0.113.8"), "no address of its own: the routing table sends it through the tunnel")
        XCTAssertTrue(off("", "198.51.100.3"), "routed outside the tunnel (split tunnel)")
        XCTAssertTrue(off("", "198.51.100.99"), "no route")
        XCTAssertFalse(off("", ""), "unconnected, the Internet's route is the tunnel")
        XCTAssertTrue(off("", "", routes: [:]), "unconnected, the Internet's route is Wi-Fi")
        XCTAssertFalse(off("192.168.178.39", "192.168.178.1"), "the local network never needs a VPN")
        XCTAssertFalse(off("127.0.0.1", "127.0.0.1"))
        XCTAssertFalse(off("127.0.0.1", ""), "bound to loopback, not connected")
        XCTAssertTrue(off("192.168.178.39", "203.0.113.8", tunnels: [:]), "no VPN up")
        XCTAssertTrue(off("100.127.80.66", "203.0.113.8", tunnels: [:]), "the tunnel's address is gone: the VPN dropped")
        XCTAssertTrue(off("", "203.0.113.8", tunnels: [:]), "a stale route without a tunnel")
    }
}
