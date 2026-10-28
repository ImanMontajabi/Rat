import XCTest
import RatFilterCore
import RatMonitor
@testable import Rat

/// Incoming connections (a peer connected to a port of this Mac) are rows of their own with no ✗/✓, and long-lived
/// connections that mostly receive are marked as streams.
@MainActor
final class DirectionAppTests: XCTestCase {
    let steam = "/Applications/Demo/Steam.app"
    var main: String { steam + "/Contents/MacOS/Steam" }
    let peer = "198.51.100.40"

    private func ledger(_ addresses: [String]) throws -> Ledger {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("rat-direction-\(UUID())")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        addTeardownBlock { try? FileManager.default.removeItem(at: dir) }
        // Reverse lookups that have answered (no names), so every connection is judged on the first pass.
        let names = HostNames(resolve: { _ in nil })
        for a in addresses { _ = names.lookup(a) }
        let deadline = Date().addingTimeInterval(5)
        while !addresses.allSatisfy({ names.lookup($0).settled }), Date() < deadline { RunLoop.current.run(until: Date().addingTimeInterval(0.02)) }
        return Ledger(directory: dir, helperInstalled: false, names: names)
    }

    private func tcp(_ pid: Int32 = 630, _ path: String? = nil, local: Int, _ remote: String = "", _ remotePort: Int = 0, state: String = "ESTABLISHED") -> ObservedConnection {
        ObservedConnection(pid: pid, processPath: path ?? main, proto: .tcp, remoteAddress: remote, remotePort: remotePort, localPort: local, tcpState: state,
                           localAddress: "192.168.1.4")
    }

    /// Steam listens on 27036; the peer connected to it twice and Steam also connected to the peer's port 443.
    private var remotePlay: [ObservedConnection] {
        [tcp(local: 27036, state: "LISTEN"), tcp(local: 27036, peer, 51000), tcp(local: 27036, peer, 51001), tcp(local: 50500, peer, 443)]
    }

    func testAPeersConnectionsToAListenerAreOneIncomingRowWithoutAToggle() async throws {
        let l = try ledger([peer])
        await l.ingest(remotePlay, [])
        let app = try XCTUnwrap(l.apps.first { $0.id == steam })
        XCTAssertEqual(app.listening, 1)
        XCTAssertEqual(app.remotes.count, 2, "the peer's two connections to 27036 are one row, Steam's own is another")
        let incoming = try XCTUnwrap(app.remotes.first(where: \.incoming))
        XCTAssertEqual(incoming.port, 27036, "the port of this Mac it connected to, not the peer's own")
        XCTAssertEqual(incoming.address, peer)
        XCTAssertNil(app.ruleTarget(process: incoming.process, remote: incoming), "rules decide what this Mac connects to: no ✗/✓")
        let outgoing = try XCTUnwrap(app.remotes.first { !$0.incoming })
        XCTAssertEqual(outgoing.port, 443)
        XCTAssertNotEqual(incoming.id, outgoing.id)
        XCTAssertNotNil(app.ruleTarget(process: outgoing.process, remote: outgoing))
        XCTAssertEqual(RouteBadges.items(incoming, compact: true).map(\.text), ["Incoming"])
        XCTAssertTrue(RouteSummaryBadges.items(app.remotes).isEmpty, "the app's row keeps its room for routes")
    }

    /// The listener can be another process's: launchd listens and hands each connection to the service it starts.
    func testAListenerOfAnotherProcessCounts() async throws {
        let l = try ledger([peer])
        let launchd = ObservedConnection(pid: 1, processPath: "/sbin/launchd", proto: .tcp, remoteAddress: "", remotePort: 0, localPort: 22, tcpState: "LISTEN")
        await l.ingest([launchd, tcp(900, "/usr/libexec/sshd-session", local: 22, peer, 52000)], [])
        let row = try XCTUnwrap(l.apps.flatMap(\.remotes).first { $0.address == peer })
        XCTAssertTrue(row.incoming)
        XCTAssertEqual(row.port, 22)
        let filter = MonitorFilter(onlyIncoming: true)
        XCTAssertTrue(filter.apps(l, settings: .shared).contains { $0.remotes.contains(where: \.incoming) }, "Only Incoming keeps the app that holds it")
    }

    /// An incoming connection never raises an alert, and the app's ✗ still cuts it (the helper blocks every socket).
    func testIncomingNeverAsksAndFollowsTheAppsDeny() async throws {
        let l = try ledger([peer])
        l.rules.silentMode = .off
        await l.ingest(remotePlay, [])
        var app = try XCTUnwrap(l.apps.first { $0.id == steam })
        XCTAssertNil(app.remotes.first(where: \.incoming)?.verdict, "not asked about")
        XCTAssertEqual(app.remotes.first { !$0.incoming }?.verdict, .ask)
        XCTAssertEqual(l.unconfirmedCount, 1, "only Steam's own connection")

        l.setPolicy(.deny, for: steam)
        await l.ingest(remotePlay, [])
        app = try XCTUnwrap(l.apps.first { $0.id == steam })
        XCTAssertEqual(app.remotes.first(where: \.incoming)?.verdict, .deny)
        XCTAssertTrue(l.deniedAppPaths.contains(steam))
    }

    func testALongDownloadIsAStreamAndADuplexConnectionIsNot() async throws {
        let l = try ledger(["203.0.113.5", "203.0.113.6", peer])
        l.streams = StreamDetector(minimumAge: 0, quietLimit: 60)
        let conns = remotePlay + [tcp(local: 50600, "203.0.113.5", 443), tcp(local: 50700, "203.0.113.6", 443)]
        func flows(_ k: UInt64) -> [FlowCounter] {
            [FlowCounter(pid: 630, proto: .tcp, localPort: 50600, remoteAddress: "203.0.113.5", remotePort: 443, bytesIn: k * 400_000, bytesOut: 2_000),
             FlowCounter(pid: 630, proto: .tcp, localPort: 50700, remoteAddress: "203.0.113.6", remotePort: 443, bytesIn: k * 300_000, bytesOut: k * 250_000),
             FlowCounter(pid: 630, proto: .tcp, localPort: 27036, remoteAddress: peer, remotePort: 51000, bytesIn: k * 900_000, bytesOut: 10)]
        }
        await l.ingest(conns, [], flows: flows(1))
        XCTAssertFalse(l.apps.flatMap(\.remotes).contains(where: \.stream), "no growth seen yet")
        await l.ingest(conns, [], flows: flows(2))
        let rows = try XCTUnwrap(l.apps.first { $0.id == steam }).remotes
        XCTAssertEqual(rows.first { $0.address == "203.0.113.5" }?.stream, true)
        XCTAssertEqual(rows.first { $0.address == "203.0.113.6" }?.stream, false, "talks both ways")
        XCTAssertEqual(rows.first(where: \.incoming)?.stream, false, "an incoming row is tagged as incoming only")
        let stream = try XCTUnwrap(rows.first { $0.address == "203.0.113.5" })
        XCTAssertEqual(RouteBadges.items(stream, compact: true).map(\.text), ["stream"])
        XCTAssertNotNil(l.apps.first { $0.id == steam }?.ruleTarget(process: stream.process, remote: stream), "a stream this Mac opened keeps its ✗/✓")

        await l.ingest([], [])
        XCTAssertEqual(l.streams.count, 0, "closed sockets are forgotten")
    }
}
