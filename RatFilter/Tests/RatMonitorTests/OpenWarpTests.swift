import Darwin
import Foundation
import XCTest
@testable import RatMonitor

/// OpenWarp, the companion WARP client: its status, its carrier socket, where its tunnel leads.
final class OpenWarpTests: XCTestCase {
    /// The shape of `GET /v1/status` from OpenWarp 0.2 in Traffic and DNS mode (registration details left out).
    static let connected = Data(#"""
    {"status":"Connected","mode":"warp","mode_label":"Traffic and DNS (UDP)","protocol":"masque","registered":true,
     "warp_plus":true,"interface":"utun4","interface_v4":"172.16.0.2","interface_v6":"2606:4700:110:8b0d::1",
     "dns_protocol":"udp (via tunnel)","tunnel":{"protocol":"MASQUE (HTTP/3)","endpoint":"162.159.198.2:443","tx_bytes":2207109,
     "rx_bytes":2381253},"network":"wifi","colo":"DUS","loc":"DE","version":"0.2.0","protection":{"state":"verified","kill_switch":"off"}}
    """#.utf8)

    func testParsesTheStatus() throws {
        let s = try XCTUnwrap(OpenWarpStatus.parse(json: Self.connected, pid: 627))
        XCTAssertEqual(s, OpenWarpStatus(pid: 627, connected: true, mode: "warp", transport: "MASQUE (HTTP/3)", interface: "utun4",
                                         endpoint: .init(address: "162.159.198.2", port: 443), colo: "DUS", loc: "DE"))
    }

    func testAStatusWithoutTheExitIsStillUsable() throws {
        // OpenWarp 0.1, or the lookup switched off: no colo/loc.
        let json = Data(#"{"status":"Connected","mode":"warp","interface":"utun4","tunnel":{"protocol":"WireGuard","endpoint":"[2606:4700:d0::a29f:c001]:2408"}}"#.utf8)
        let s = try XCTUnwrap(OpenWarpStatus.parse(json: json, pid: 1))
        XCTAssertEqual(s.endpoint, .init(address: "2606:4700:d0::a29f:c001", port: 2408))
        XCTAssertNil(s.colo); XCTAssertNil(s.loc)
    }

    func testDisconnectedHasNoTunnel() throws {
        let json = Data(#"{"status":"Disconnected","mode":"warp","interface":"utun4","tunnel":{"endpoint":"162.159.198.2:443"},"colo":"DUS","loc":"DE"}"#.utf8)
        let s = try XCTUnwrap(OpenWarpStatus.parse(json: json, pid: 1))
        XCTAssertFalse(s.connected)
        XCTAssertNil(s.interface); XCTAssertNil(s.endpoint); XCTAssertNil(s.colo)
    }

    func testMalformedFieldsAreDropped() throws {
        let json = Data(#"{"status":"Connected","mode":"warp","interface":"utun4; rm -rf /","tunnel":{"endpoint":"evil.example:443"},"colo":"dus","loc":"XX"}"#.utf8)
        let s = try XCTUnwrap(OpenWarpStatus.parse(json: json, pid: 1))
        XCTAssertNil(s.interface); XCTAssertNil(s.endpoint); XCTAssertNil(s.colo); XCTAssertNil(s.loc)
        XCTAssertNil(OpenWarpStatus.parse(json: Data("not json".utf8), pid: 1))
        XCTAssertNil(OpenWarpStatus.parse(json: Data(#"{"mode":"warp"}"#.utf8), pid: 1), "no status")
        XCTAssertNil(OpenWarpStatus.parse(json: Data(repeating: 0x20, count: OpenWarpStatus.maxResponse + 1), pid: 1), "too large")
    }

    func testEndpoints() {
        XCTAssertEqual(OpenWarpStatus.endpoint("162.159.198.2:443"), .init(address: "162.159.198.2", port: 443))
        XCTAssertEqual(OpenWarpStatus.endpoint("[2606:4700:d0::a29f:c001]:500"), .init(address: "2606:4700:d0::a29f:c001", port: 500))
        for bad in ["162.159.198.2", "162.159.198.2:0", "162.159.198.2:70000", "host.example:443", ":443", "1.2.3:443", ""] {
            XCTAssertNil(OpenWarpStatus.endpoint(bad), bad)
        }
    }

    func testHTTPFraming() throws {
        let ok = Data("HTTP/1.0 200 OK\r\nContent-Type: application/json\r\n\r\n".utf8) + Self.connected
        XCTAssertEqual(try XCTUnwrap(OpenWarpStatus.parse(http: ok, pid: 9)).colo, "DUS")
        XCTAssertNil(OpenWarpStatus.parse(http: Data("HTTP/1.1 403 Forbidden\r\n\r\n{}".utf8), pid: 9))
        XCTAssertNil(OpenWarpStatus.parse(http: Self.connected, pid: 9), "no header")
    }

    // MARK: the control socket

    /// A one-shot server on a Unix socket in a short temporary folder, answering like OpenWarp's daemon.
    private func serve(_ response: Data) throws -> (path: String, done: XCTestExpectation) {
        let dir = "/tmp/rat-ow-\(getpid())-\(UInt32.random(in: 0...UInt32.max))"
        try FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
        addTeardownBlock { try? FileManager.default.removeItem(atPath: dir) }
        let path = dir + "/s.sock"
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        withUnsafeMutableBytes(of: &addr.sun_path) { raw in let b = Array(path.utf8); raw.copyBytes(from: b); raw[b.count] = 0 }
        let bound = withUnsafePointer(to: &addr) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.bind(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) } }
        // A client that refuses the peer hangs up before the answer. SO_NOSIGPIPE goes on the listening socket, which
        // the accepted one inherits: set after accept, it fails (EINVAL) on a socket whose client has already gone,
        // and the write below would kill the test process with SIGPIPE.
        var one: Int32 = 1
        XCTAssertEqual(setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, socklen_t(MemoryLayout<Int32>.size)), 0)
        XCTAssertEqual(bound, 0); XCTAssertEqual(Darwin.listen(fd, 1), 0)
        let done = expectation(description: "served")
        Thread.detachNewThread {
            let c = Darwin.accept(fd, nil, nil)
            var buf = [UInt8](repeating: 0, count: 1024)
            // No request (the client hung up): nothing to answer.
            if Darwin.read(c, &buf, buf.count) > 0 {
                _ = response.withUnsafeBytes { Darwin.write(c, $0.baseAddress, $0.count) }
            }
            close(c); close(fd)
            done.fulfill()
        }
        return (path, done)
    }

    func testReadsTheStatusFromTheControlSocket() throws {
        let (path, done) = try serve(Data("HTTP/1.0 200 OK\r\n\r\n".utf8) + Self.connected)
        // This test process answers: it stands in for the helper, as owner and peer.
        let me = ConnectionSampler.path(of: getpid())
        let s = try XCTUnwrap(OpenWarpStatus.read(socket: path, peer: me, owner: getuid()))
        XCTAssertEqual(s.pid, getpid()); XCTAssertEqual(s.colo, "DUS")
        wait(for: [done], timeout: 2)
    }

    func testRefusesAnotherProgramOnTheSocket() throws {
        let (path, done) = try serve(Data("HTTP/1.0 200 OK\r\n\r\n".utf8) + Self.connected)
        XCTAssertNil(OpenWarpStatus.read(socket: path, peer: OpenWarpStatus.helperPath, owner: getuid()), "the peer is not OpenWarp's helper")
        wait(for: [done], timeout: 2)
        XCTAssertNil(OpenWarpStatus.read(socket: path, peer: ConnectionSampler.path(of: getpid()), owner: 0), "a socket root does not own")
    }

    func testRefusesAFileThatIsNotASocket() throws {
        let file = NSTemporaryDirectory() + "rat-ow-\(getpid()).txt"
        try Data("HTTP/1.0 200 OK\r\n\r\n{}".utf8).write(to: URL(fileURLWithPath: file))
        defer { try? FileManager.default.removeItem(atPath: file) }
        XCTAssertNil(OpenWarpStatus.read(socket: file, peer: ConnectionSampler.path(of: getpid()), owner: getuid()))
        XCTAssertNil(OpenWarpStatus.read(socket: "/nonexistent/openwarp.sock"))
    }

    func testTheLinkReadsAtMostEveryInterval() {
        var reads = 0
        var present = true
        let link = OpenWarpLink(interval: 5, present: { present }, reader: { reads += 1; return OpenWarpStatus(pid: 1, connected: true, mode: "warp") })
        let t0 = Date(timeIntervalSince1970: 1_000)
        XCTAssertNotNil(link.current(now: t0))
        XCTAssertNotNil(link.current(now: t0 + 4.9))
        XCTAssertEqual(reads, 1)
        _ = link.current(now: t0 + 5)
        XCTAssertEqual(reads, 2)
        present = false
        XCTAssertNil(link.current(now: t0 + 10), "no socket: not running")
        XCTAssertEqual(reads, 2, "nothing is read without the socket")
    }

    // MARK: the carrier and the tunnel

    private let status = OpenWarpStatus(pid: 627, connected: true, mode: "warp", interface: "utun4",
                                        endpoint: .init(address: "162.159.198.2", port: 443), colo: "DUS", loc: "DE")

    func testTheUnconnectedSocketBecomesTheCarrier() {
        let helper = OpenWarpStatus.helperPath
        let conns = [
            ObservedConnection(pid: 627, processPath: helper, proto: .udp, remoteAddress: "", remotePort: 0, localPort: 53818, tcpState: nil),
            // The DNS stub on loopback and a listener stay as they are.
            ObservedConnection(pid: 627, processPath: helper, proto: .udp, remoteAddress: "", remotePort: 0, localPort: 53, tcpState: nil, localAddress: "127.0.0.1"),
            ObservedConnection(pid: 627, processPath: helper, proto: .tcp, remoteAddress: "", remotePort: 0, localPort: 40000, tcpState: "LISTEN", localAddress: "127.0.0.1"),
            // Another program's unconnected socket is not OpenWarp's.
            ObservedConnection(pid: 700, processPath: "/usr/libexec/rapportd", proto: .udp, remoteAddress: "", remotePort: 0, localPort: 3722, tcpState: nil),
        ]
        let out = TunnelCarrier.resolve(conns, openWarp: status)
        XCTAssertEqual(out[0].remoteAddress, "162.159.198.2"); XCTAssertEqual(out[0].remotePort, 443)
        XCTAssertTrue(out[0].carrier); XCTAssertTrue(out[0].isOutbound)
        XCTAssertEqual(Array(out[1...]), Array(conns[1...]))
        // Disconnected, or no endpoint: nothing is named.
        var off = status; off.connected = false
        XCTAssertEqual(TunnelCarrier.resolve(conns, openWarp: off), conns)
        XCTAssertEqual(TunnelCarrier.resolve(conns, openWarp: nil), conns)
    }

    /// From the root helper's lsof lines (as Rat's snapshot reads them live) to the carrier: the socket without a
    /// peer is kept only for OpenWarp's pid, and becomes its connection to the endpoint.
    func testTheSnapshotKeepsOpenWarpsCarrierSocket() throws {
        let text = """
        p627
        f12
        PUDP
        n*:53818
        f13
        PUDP
        n127.0.0.1:53819
        p200
        f3
        PUDP
        n*:5353
        #PS
          627 /Library/PrivilegedHelperTools/com.local.openwarp
          200 /usr/sbin/mDNSResponder
        """
        XCTAssertTrue(SystemSnapshot.parse(text, listeners: true).isEmpty, "no socket without a peer unless asked")
        let kept = SystemSnapshot.parse(text, listeners: true, unconnectedUDP: [627])
        XCTAssertEqual(kept.map(\.localPort), [53818, 53819], "only OpenWarp's, never mDNSResponder's")
        let warp = OpenWarpStatus(pid: 627, connected: true, mode: "warp", transport: "MASQUE (HTTP/3)", interface: "utun4",
                                  endpoint: .init(address: "162.159.198.2", port: 443), colo: "DUS", loc: "DE")
        let resolved = TunnelCarrier.resolve(kept, openWarp: warp)
        let carrier = try XCTUnwrap(resolved.first { $0.carrier })
        XCTAssertEqual(carrier.localPort, 53818)
        XCTAssertEqual(carrier.remoteAddress, "162.159.198.2"); XCTAssertEqual(carrier.remotePort, 443)
        XCTAssertEqual(carrier.processPath, OpenWarpStatus.helperPath)
        XCTAssertTrue(carrier.isOutbound)
        XCTAssertEqual(resolved.filter(\.carrier).count, 1, "a loopback socket is not the carrier")
    }

    func testWARPEndpointsAreAnycast() {
        for a in ["162.159.198.2", "162.159.192.1", "162.159.193.10", "162.159.197.3", "2606:4700:d0::a29f:c001", "2606:4700:d1::1", "2606:4700:102::3"] {
            XCTAssertTrue(CloudflareWARP.isEndpoint(a), a)
        }
        for a in ["162.159.200.1", "162.159.199.1", "1.1.1.1", "2606:4700:4700::1111", "2606:4700:d2::1", "not an address", ""] {
            XCTAssertFalse(CloudflareWARP.isEndpoint(a), a)
        }
    }

    func testOpenWarpsTunnelExitsWhereItReports() {
        let canada: (String) -> String? = { _ in "CA" }   // what a database says for 162.159.198.0/23
        XCTAssertEqual(TunnelPlacement.carriers(of: "utun4", found: [], openWarp: status), ["162.159.198.2"])
        XCTAssertEqual(TunnelPlacement.country(of: "utun4", carriers: ["162.159.198.2"], lookup: canada, openWarp: status), "DE")
        var unknown = status; unknown.loc = nil
        XCTAssertNil(TunnelPlacement.country(of: "utun4", carriers: ["162.159.198.2"], lookup: canada, openWarp: unknown), "not Canada")
        // Without OpenWarp's status (the official client, or OpenWarp 0.1): WARP endpoints are unknown, others as before.
        XCTAssertNil(TunnelPlacement.country(of: "utun4", carriers: ["162.159.198.2"], lookup: canada, openWarp: nil))
        XCTAssertEqual(TunnelPlacement.country(of: "utun3", carriers: ["203.0.113.9"], lookup: { _ in "NL" }, openWarp: status), "NL")
        XCTAssertEqual(TunnelPlacement.carriers(of: "utun3", found: ["203.0.113.9"], openWarp: status), ["203.0.113.9"])
        XCTAssertEqual(TunnelPlacement.serverCountry("162.159.198.2", lookup: canada, openWarp: status), "DE")
        XCTAssertNil(TunnelPlacement.serverCountry("162.159.192.1", lookup: canada, openWarp: status))
        XCTAssertEqual(TunnelPlacement.serverCountry("203.0.113.9", lookup: canada, openWarp: status), "CA")
    }

    // MARK: identity

    func testTheHelperBelongsToTheApp() {
        let owner = ProcessGrouping.owner(of: OpenWarpStatus.helperPath, responsiblePath: { nil })
        XCTAssertEqual(owner, .app(bundle: "/Applications/OpenWarp.app", isExtension: false))
        XCTAssertEqual(owner.ruleKey, "/Applications/OpenWarp.app")
        XCTAssertEqual(ProcessGrouping.owner(of: "/Applications/OpenWarp.app/Contents/Resources/openwarp", responsiblePath: { nil }).ruleKey,
                       "/Applications/OpenWarp.app", "the bundled CLI")
        XCTAssertEqual(ProcessGrouping.companionBundleIdentifier(of: "/Applications/OpenWarp.app"), "local.openwarp.app")
    }

    func testTheVPNIsNamedOpenWarp() {
        XCTAssertEqual(NetworkRoutes.knownApp(inPath: OpenWarpStatus.helperPath), "OpenWarp")
        XCTAssertEqual(NetworkRoutes.knownApp(inPath: "/Applications/Cloudflare WARP.app/Contents/Resources/CloudflareWARP"), "Cloudflare WARP")
        XCTAssertEqual(NetworkRoutes.localProxyProgram(inPath: OpenWarpStatus.helperPath), "OpenWarp", "its proxy mode on 127.0.0.1:40000")
    }

    func testTheTotalCountsTheLineNotTheTunnel() {
        // OpenWarp routes 0/1 and 128.0/1 into its utun and leaves the default route on Wi-Fi: Wi-Fi is the line.
        XCTAssertEqual(InternetTraffic.internetInterfaces(defaultRoutes: ["en0"]), ["en0"])
        XCTAssertEqual(InternetTraffic.internetInterfaces(defaultRoutes: ["en0", "utun4"]), ["en0"])
        var t = InternetTraffic()
        _ = t.update([InterfaceCounter(name: "en0", bytesIn: 0, bytesOut: 0), InterfaceCounter(name: "utun4", bytesIn: 0, bytesOut: 0)], internet: ["en0"])
        // 1 MB through the tunnel arrives as about 1.05 MB of QUIC on Wi-Fi: counted once, as the line carried it.
        let d = t.update([InterfaceCounter(name: "en0", bytesIn: 1_050_000, bytesOut: 60_000), InterfaceCounter(name: "utun4", bytesIn: 1_000_000, bytesOut: 50_000)], internet: ["en0"])
        XCTAssertEqual(d.bytesIn, 1_050_000); XCTAssertEqual(d.bytesOut, 60_000)
    }
}
