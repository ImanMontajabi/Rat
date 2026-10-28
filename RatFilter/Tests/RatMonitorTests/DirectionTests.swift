import XCTest
@testable import RatMonitor

/// Who started a connection (`SocketDirection`) and which ones are long-lived download streams (`StreamDetector`).
final class DirectionTests: XCTestCase {
    private func tcp(_ pid: Int32, local: String = "", _ localPort: Int, _ remote: String = "", _ remotePort: Int = 0, state: String = "ESTABLISHED") -> ObservedConnection {
        ObservedConnection(pid: pid, processPath: "/usr/sbin/sshd", proto: .tcp, remoteAddress: remote, remotePort: remotePort, localPort: localPort,
                           tcpState: state, localAddress: local)
    }

    /// Real sockets of this test process: a listener on loopback, a client connected to it, and the connection the
    /// listener accepted. Only the accepted one was started by a peer.
    func testOnRealSocketsOnlyTheAcceptedConnectionIsIncoming() throws {
        let listener = socket(AF_INET, SOCK_STREAM, 0)
        defer { close(listener) }
        var addr = sockaddr_in(); addr.sin_family = sa_family_t(AF_INET); addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        addr.sin_addr.s_addr = UInt32(0x7f000001).bigEndian
        let size = socklen_t(MemoryLayout<sockaddr_in>.size)
        XCTAssertEqual(withUnsafePointer(to: &addr) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.bind(listener, $0, size) } }, 0)
        XCTAssertEqual(Darwin.listen(listener, 4), 0)
        var bound = sockaddr_in(); var len = size
        _ = withUnsafeMutablePointer(to: &bound) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(listener, $0, &len) } }
        let port = Int(UInt16(bigEndian: bound.sin_port))

        let client = socket(AF_INET, SOCK_STREAM, 0)
        defer { close(client) }
        addr.sin_port = bound.sin_port
        XCTAssertEqual(withUnsafePointer(to: &addr) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.connect(client, $0, size) } }, 0)
        let accepted = Darwin.accept(listener, nil, nil)
        defer { close(accepted) }
        XCTAssertGreaterThan(accepted, 0)

        let mine = SocketDirection.mark(ConnectionSampler.connections(of: getpid()))
        let atListener = mine.filter { $0.proto == .tcp && $0.localPort == port }
        let listening = try XCTUnwrap(atListener.first { $0.tcpState == "LISTEN" })
        XCTAssertFalse(listening.incoming, "the listener itself is no connection")
        let inbound = try XCTUnwrap(atListener.first { $0.tcpState != "LISTEN" }, "the accepted socket holds the listener's port")
        XCTAssertTrue(inbound.incoming)
        let outbound = try XCTUnwrap(mine.first { $0.proto == .tcp && $0.remotePort == port && $0.localPort == inbound.remotePort })
        XCTAssertFalse(outbound.incoming, "the client started its connection")
    }

    func testAListenerOnAnyAddressOrTheSameOneMakesItsConnectionsIncoming() {
        let marked = SocketDirection.mark([
            tcp(1, 22, state: "LISTEN"),
            tcp(2, local: "192.168.1.4", 22, "192.168.1.20", 51000),              // accepted by sshd launched by launchd
            tcp(3, local: "127.0.0.1", 8080, state: "LISTEN"),
            tcp(3, local: "127.0.0.1", 8080, "127.0.0.1", 51001),
            tcp(4, local: "192.168.1.4", 8080, "203.0.113.5", 443),              // same port, another address: outgoing
            tcp(5, local: "192.168.1.4", 52000, "203.0.113.5", 22),              // to a server's port 22: outgoing
            ObservedConnection(pid: 6, processPath: "/x", proto: .udp, remoteAddress: "192.168.1.20", remotePort: 5000, localPort: 22, tcpState: nil),
        ])
        XCTAssertEqual(marked.map(\.incoming), [false, true, false, true, false, false, false])
    }

    func testAnIPv6ListenerOnAnIPv4AddressMatchesTheMappedForm() {
        let marked = SocketDirection.mark([tcp(1, local: "127.0.0.1", 9000, state: "LISTEN"), tcp(1, local: "::ffff:127.0.0.1", 9000, "::ffff:127.0.0.1", 60000)])
        XCTAssertTrue(marked[1].incoming)
    }

    func testWithoutListenersNothingIsIncoming() {
        let conns = [tcp(1, local: "192.168.1.4", 22, "192.168.1.20", 51000)]
        XCTAssertEqual(SocketDirection.mark(conns), conns)
    }

    func testTheHelpersSnapshotKeepsListenersWhenAsked() {
        let text = """
        p1
        f7
        PTCP
        n*:22
        TST=LISTEN
        f8
        PTCP
        n[::1]:631
        TST=LISTEN
        f9
        PUDP
        n*:5353
        p2
        f4
        PTCP
        n192.168.1.4:22->192.168.1.20:51000
        TST=ESTABLISHED
        #PS
            1 /sbin/launchd
            2 /usr/libexec/sshd-session
        """
        XCTAssertEqual(SystemSnapshot.parse(text).count, 1, "connections only by default")
        let all = SystemSnapshot.parse(text, listeners: true)
        XCTAssertEqual(all.map(\.localPort), [22, 631, 22])
        XCTAssertEqual(all.map(\.localAddress), ["", "::1", "192.168.1.4"])
        XCTAssertEqual(all[0].tcpState, "LISTEN")
        XCTAssertTrue(SocketDirection.mark(all)[2].incoming, "sshd's connection, accepted on launchd's listener")
    }

    func testAStreamIsLongLivedMostlyReceivingAndStillReceiving() {
        var d = StreamDetector()
        let t0 = Date(), key = "1|tcp|50000|203.0.113.5|443"
        XCTAssertFalse(d.update(key, bytesIn: 10_000, bytesOut: 2_000, now: t0))
        XCTAssertFalse(d.update(key, bytesIn: 200_000, bytesOut: 3_000, now: t0.addingTimeInterval(20)), "not open long enough")
        XCTAssertTrue(d.update(key, bytesIn: 400_000, bytesOut: 4_000, now: t0.addingTimeInterval(31)))
        XCTAssertTrue(d.update(key, bytesIn: 400_000, bytesOut: 4_000, now: t0.addingTimeInterval(40)), "a pause shorter than the quiet limit")
        XCTAssertFalse(d.update(key, bytesIn: 400_000, bytesOut: 4_000, now: t0.addingTimeInterval(42)), "stopped receiving")
        XCTAssertTrue(d.update(key, bytesIn: 401_000, bytesOut: 4_000, now: t0.addingTimeInterval(45)), "receives again")
    }

    func testDuplexSmallAndIdleSocketsAreNoStreams() {
        var d = StreamDetector()
        let t0 = Date()
        _ = d.update("duplex", bytesIn: 0, bytesOut: 0, now: t0)
        XCTAssertFalse(d.update("duplex", bytesIn: 500_000, bytesOut: 300_000, now: t0.addingTimeInterval(60)), "a WebSocket that talks both ways")
        _ = d.update("small", bytesIn: 0, bytesOut: 0, now: t0)
        XCTAssertFalse(d.update("small", bytesIn: 4_000, bytesOut: 100, now: t0.addingTimeInterval(60)), "too little to call a stream")
        XCTAssertFalse(d.update("idle", bytesIn: 900_000, bytesOut: 100, now: t0))
        XCTAssertFalse(d.update("idle", bytesIn: 900_000, bytesOut: 100, now: t0.addingTimeInterval(60)), "a page loaded before and nothing since")
        d.keep(only: ["duplex"])
        XCTAssertEqual(d.count, 1)
    }
}
