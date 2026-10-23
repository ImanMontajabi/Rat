import XCTest
import RatFilterCore
import RatMonitor
import RatEnforce
@testable import Rat

/// 1.1.0: connections through local proxies (SSH tunnels, SOCKS and HTTP proxies) show their real destination.
@MainActor
final class Release110Tests: XCTestCase {
    private let curl = "/opt/homebrew/bin/curl", ssh = "/usr/bin/ssh"

    private func conns() -> [ObservedConnection] {
        [
            ObservedConnection(pid: 500, processPath: curl, proto: .tcp, remoteAddress: "127.0.0.1", remotePort: 1080, localPort: 61000, tcpState: "ESTABLISHED"),
            ObservedConnection(pid: 77, processPath: ssh, proto: .tcp, remoteAddress: "", remotePort: 0, localPort: 1080, tcpState: "LISTEN"),
            ObservedConnection(pid: 77, processPath: ssh, proto: .tcp, remoteAddress: "127.0.0.1", remotePort: 61000, localPort: 1080, tcpState: "ESTABLISHED"),
            ObservedConnection(pid: 77, processPath: ssh, proto: .tcp, remoteAddress: "203.0.113.7", remotePort: 22, localPort: 52000, tcpState: "ESTABLISHED"),
        ]
    }

    private func flow(_ host: String, clientPort: Int = 61000, closed: Date? = nil) -> ProxiedFlow {
        ProxiedFlow(kind: .socks5, host: host, port: 443, clientPID: 500, clientPath: curl, clientPort: clientPort, proxyPort: 1080,
                    proxyPID: 77, proxyPath: ssh, seen: Date(), closed: closed)
    }

    func testUnmaskedDestinationKeepsTheProxyHop() {
        let now = Date()
        let r = ProxyUnmasking.unmask(flows: [flow("api.github.com"), flow("old.example", clientPort: 61001, closed: now.addingTimeInterval(-60))],
                                      conns: conns(), now: now, arguments: { _ in nil })
        XCTAssertEqual(r.remotes.map(\.host), ["api.github.com"], "a connection closed a minute ago is no longer shown")
        let hop = r.remotes[0].hop
        XCTAssertEqual(hop.label, "via ssh proxy (127.0.0.1:1080 → 203.0.113.7)")
        XCTAssertEqual(hop.kind, "SOCKS5")
        XCTAssertEqual(r.masked, ["500|61000|1080"], "the client's loopback socket is replaced by the real destination")
    }

    func testCommandLineFallbackWhenTheHelperSawNothing() {
        let args = ProcessArguments(targets: [.init(host: "example.com", port: 443)], proxies: [.init(host: "127.0.0.1", port: 1080)])
        let r = ProxyUnmasking.unmask(flows: [], conns: conns(), now: Date(), arguments: { $0 == 500 ? args : nil })
        XCTAssertEqual(r.remotes.map { "\($0.host):\($0.port) \($0.hop.kind) \($0.hop.process)" }, ["example.com:443 command line ssh"])
        // Without a proxy setting pointing at that port, a loopback connection is just a local connection.
        let local = ProxyUnmasking.unmask(flows: [], conns: conns(), now: Date(), arguments: { _ in ProcessArguments(targets: [.init(host: "example.com", port: 443)], proxies: []) })
        XCTAssertTrue(local.remotes.isEmpty)
    }

    func testProxyWithSeveralServersNamesNone() {
        var c = conns()
        c.append(ObservedConnection(pid: 77, processPath: ssh, proto: .tcp, remoteAddress: "198.51.100.9", remotePort: 22, localPort: 52001, tcpState: "ESTABLISHED"))
        let r = ProxyUnmasking.unmask(flows: [flow("a.example")], conns: c, now: Date(), arguments: { _ in nil })
        XCTAssertNil(r.remotes.first?.hop.server)
        XCTAssertEqual(r.remotes.first?.hop.label, "via ssh proxy (127.0.0.1:1080)")
    }

    /// End to end through the ledger: the helper's flow file → the client's connection list → a rule denying the
    /// real destination makes Rat hand the daemon the client's loopback port.
    func testLedgerShowsAndDeniesProxiedDestinations() async throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("rat-110-\(UUID())")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        AppSettings.shared.resolveProxiedHosts = false   // no DNS in tests
        let ledger = Ledger(directory: dir, helperInstalled: true)
        let enc = JSONEncoder(); enc.dateEncodingStrategy = .secondsSince1970
        try enc.encode(ProxiedFlows(updated: Date(), flows: [flow("example.com")])).write(to: dir.appendingPathComponent("proxied.json"))

        await ledger.ingest(conns(), [])
        let client = try XCTUnwrap(ledger.apps.first { $0.id == curl })
        XCTAssertEqual(client.remotes.map(\.host), ["example.com"], "the real destination replaces 127.0.0.1:1080")
        XCTAssertEqual(client.remotes.first?.via?.server, "203.0.113.7")
        let proxy = try XCTUnwrap(ledger.apps.first { $0.identity.id == "macOS" })
        XCTAssertTrue(proxy.remotes.contains { $0.address == "203.0.113.7" && $0.via == nil }, "ssh and its server stay visible")

        ledger.rules.ruleSet.rules.append(Rule(verdict: .deny, processPath: curl, remoteDomain: "example.com", profileID: ledger.rules.ruleSet.activeProfileID))
        await ledger.ingest(conns(), [])
        ledger.refreshEnforcement()
        let ports = try String(contentsOf: dir.appendingPathComponent("denied-ports.txt"), encoding: .utf8)
        XCTAssertEqual(ports, "lo0 61000\n", "only the client's loopback connection is cut, nothing by address")
        XCTAssertEqual(ledger.deniedCount, 1)

        // Once the connection closed, its port is no longer handed to the daemon (another program may reuse it),
        // though the destination stays listed for a few seconds.
        try enc.encode(ProxiedFlows(updated: Date(), flows: [flow("example.com", closed: Date())])).write(to: dir.appendingPathComponent("proxied.json"))
        await ledger.ingest(conns(), [])
        ledger.refreshEnforcement()
        XCTAssertEqual(try String(contentsOf: dir.appendingPathComponent("denied-ports.txt"), encoding: .utf8), "")
        XCTAssertEqual(ledger.apps.first { $0.id == curl }?.remotes.map(\.host), ["example.com"])
    }
}
