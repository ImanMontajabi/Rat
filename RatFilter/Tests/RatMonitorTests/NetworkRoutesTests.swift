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

    func testLocalProxyPrograms() {
        XCTAssertEqual(NetworkRoutes.localProxyProgram(inPath: "/usr/bin/ssh"), "ssh")
        XCTAssertEqual(NetworkRoutes.localProxyProgram(inPath: "/opt/homebrew/bin/tor"), "Tor")
        XCTAssertEqual(NetworkRoutes.localProxyProgram(inPath: "/opt/homebrew/bin/mitmdump"), "mitmproxy")
        XCTAssertEqual(NetworkRoutes.localProxyProgram(inPath: "/Applications/ClashX.app/Contents/MacOS/ClashX"), "ClashX")
        XCTAssertNil(NetworkRoutes.localProxyProgram(inPath: "/usr/local/bin/node"), "a dev server is no proxy")
        XCTAssertNil(NetworkRoutes.localProxyProgram(inPath: "/usr/bin/sshd-keygen-wrapper"))
    }
}
