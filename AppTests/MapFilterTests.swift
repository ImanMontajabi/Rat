import XCTest
import RatMonitor
import RatEnforce
@testable import Rat

/// The map draws what the list shows: the search, the vpn / proxy words and chip, and the other chips apply to
/// both (`MonitorFilter`). A forwarding proxy's one outside connection is the destination, not a proxy server.
@MainActor
final class MapFilterTests: XCTestCase {
    private func demo() throws -> Ledger {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("rat-mapfilter-\(UUID())")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        addTeardownBlock { try? FileManager.default.removeItem(at: dir) }
        let l = Ledger(directory: dir, helperInstalled: false)
        l.installDemoData()
        return l
    }

    /// The places the map draws for a filter, as `MapPane` picks them.
    private func places(_ l: Ledger, _ f: MonitorFilter) -> Set<String> {
        var out = Set<String>()
        for a in f.apps(l, settings: .shared) {
            for r in a.remotes where f.matches(r, of: a) {
                if let g = r.geo { out.insert(g.city) }
                if let s = r.via?.serverGeo { out.insert("Proxy · \(s.city)") }
            }
        }
        return out
    }

    func testRouteChipAndWordsNarrowTheMap() throws {
        let l = try demo()
        XCTAssertTrue(places(l, MonitorFilter()).isSuperset(of: ["London", "Paris", "Madrid", "Stockholm"]))
        XCTAssertEqual(places(l, MonitorFilter(route: .vpn)), ["Paris"], "only Telegram's tunnelled connection, not its other one in Frankfurt")
        XCTAssertEqual(places(l, MonitorFilter(route: .proxy)), ["Madrid", "Proxy · Stockholm"], "the unmasked destination and its proxy server")
        XCTAssertEqual(places(l, MonitorFilter(search: "proxy")), places(l, MonitorFilter(route: .proxy)), "the search word works like the chip")
        XCTAssertEqual(places(l, MonitorFilter(search: "vpn proxy")), ["Paris", "Madrid", "Proxy · Stockholm"])
    }

    func testSearchNarrowsTheMapToMatchingConnections() throws {
        let l = try demo()
        XCTAssertEqual(places(l, MonitorFilter(search: "telegram")), ["Frankfurt", "Paris"], "an app's name: all its connections")
        XCTAssertEqual(places(l, MonitorFilter(search: "Chrome Helper")), ["Frankfurt", "Paris"], "a process's name: its connections only")
        XCTAssertEqual(places(l, MonitorFilter(search: "London")), ["London"], "a city: only the lines to it")
        XCTAssertEqual(places(l, MonitorFilter(search: "nothing-matches")), [])
        XCTAssertEqual(MapPane.summary([]), "No servers")
        XCTAssertEqual(MapPane.summary(["Proxy · Stockholm", "Madrid"]), "Madrid, Proxy · Stockholm")
    }

    func testOtherChipsApplyToTheMapToo() throws {
        let l = try demo()
        l.setPolicy(.deny, for: "/Applications/Demo/Steam.app")
        XCTAssertEqual(places(l, MonitorFilter(onlyDenied: true)), ["Stockholm", "Madrid"], "Steam's two servers")
    }

    // MARK: forwarding proxies

    private let curl = "/usr/bin/curl", python = "/usr/local/bin/python3.12", ssh = "/usr/bin/ssh"

    private func flow(_ host: String, proxy: String) -> ProxiedFlow {
        ProxiedFlow(kind: .httpConnect, host: host, port: 443, clientPID: 500, clientPath: curl, clientPort: 61000, proxyPort: 8080,
                    proxyPID: 77, proxyPath: proxy, seen: Date(), closed: nil)
    }

    private func conns(proxy: String, server: String, port: Int) -> [ObservedConnection] {
        [ObservedConnection(pid: 500, processPath: curl, proto: .tcp, remoteAddress: "127.0.0.1", remotePort: 8080, localPort: 61000, tcpState: "ESTABLISHED"),
         ObservedConnection(pid: 77, processPath: proxy, proto: .tcp, remoteAddress: "", remotePort: 0, localPort: 8080, tcpState: "LISTEN"),
         ObservedConnection(pid: 77, processPath: proxy, proto: .tcp, remoteAddress: server, remotePort: port, localPort: 52000, tcpState: "ESTABLISHED")]
    }

    func testForwardingProxyHasNoServerHop() {
        // A small proxy that connects to the destination itself: its one connection is not a hop.
        var r = ProxyUnmasking.unmask(flows: [flow("speed.example", proxy: python)], conns: conns(proxy: python, server: "198.51.100.40", port: 443), now: Date(), arguments: { _ in nil })
        XCTAssertNil(r.remotes.first?.hop.server)
        XCTAssertEqual(r.remotes.first?.hop.badge, "Proxy · python3.12")
        r = ProxyUnmasking.unmask(flows: [flow("198.51.100.40", proxy: ssh)], conns: conns(proxy: ssh, server: "198.51.100.40", port: 443), now: Date(), arguments: { _ in nil })
        XCTAssertNil(r.remotes.first?.hop.server, "the destination's own address is never its proxy server")
        // ssh -D reaches its server on port 22: that is the hop.
        r = ProxyUnmasking.unmask(flows: [flow("speed.example", proxy: ssh)], conns: conns(proxy: ssh, server: "203.0.113.7", port: 22), now: Date(), arguments: { _ in nil })
        XCTAssertEqual(r.remotes.first?.hop.server, "203.0.113.7")
        // Tor's guard may listen on 443 too; a known tunnel keeps its hop.
        r = ProxyUnmasking.unmask(flows: [flow("speed.example", proxy: "/opt/homebrew/bin/tor")], conns: conns(proxy: "/opt/homebrew/bin/tor", server: "203.0.113.8", port: 443), now: Date(), arguments: { _ in nil })
        XCTAssertEqual(r.remotes.first?.hop.server, "203.0.113.8")
    }

    func testCommandLineFallbackNamesAnIPv6Listener() {
        let c = [ObservedConnection(pid: 500, processPath: curl, proto: .tcp, remoteAddress: "::1", remotePort: 1080, localPort: 61000, tcpState: "ESTABLISHED"),
                 ObservedConnection(pid: 77, processPath: ssh, proto: .tcp, remoteAddress: "", remotePort: 0, localPort: 1080, tcpState: "LISTEN")]
        let args = ProcessArguments(targets: [.init(host: "example.com", port: 443)], proxies: [.init(host: "::1", port: 1080)])
        let r = ProxyUnmasking.unmask(flows: [], conns: c, now: Date(), arguments: { _ in args })
        XCTAssertEqual(r.remotes.first?.hop.listener, "[::1]:1080")
    }
}
