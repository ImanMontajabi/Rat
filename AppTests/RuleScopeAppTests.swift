import XCTest
import RatFilterCore
import RatMonitor
@testable import Rat

/// ✗/✓ for one process of an app and for one connection, as the ledger judges them and hands them to the helper.
@MainActor
final class RuleScopeAppTests: XCTestCase {
    let app = "/Applications/Foo.app"
    let main = "/Applications/Foo.app/Contents/MacOS/Foo"
    let updater = "/Applications/Foo.app/Contents/MacOS/Foo Updater"
    let servers = ["203.0.113.10", "203.0.113.11", "2001:db8::20"]

    private func tempDir() throws -> URL {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("rat-scope-\(UUID())")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        addTeardownBlock { try? FileManager.default.removeItem(at: dir) }
        return dir
    }

    /// A ledger whose reverse lookups have answered (no names), so every connection is judged on the first pass.
    private func ledger() throws -> (Ledger, URL) {
        let dir = try tempDir()
        let names = HostNames(resolve: { _ in nil })
        for a in servers { _ = names.lookup(a) }
        let deadline = Date().addingTimeInterval(5)
        while !servers.allSatisfy({ names.lookup($0).settled }), Date() < deadline { RunLoop.current.run(until: Date().addingTimeInterval(0.02)) }
        return (Ledger(directory: dir, helperInstalled: true, names: names), dir)
    }

    private var conns: [ObservedConnection] {
        [ObservedConnection(pid: 900, processPath: main, proto: .tcp, remoteAddress: servers[0], remotePort: 443, localPort: 51000, tcpState: "ESTABLISHED"),
         ObservedConnection(pid: 900, processPath: main, proto: .udp, remoteAddress: servers[2], remotePort: 443, localPort: 51001, tcpState: nil),
         ObservedConnection(pid: 901, processPath: updater, proto: .tcp, remoteAddress: servers[1], remotePort: 443, localPort: 51002, tcpState: "ESTABLISHED")]
    }

    private func verdict(_ l: Ledger, _ address: String) -> Verdict? {
        l.apps.first { $0.identity.ruleKey == app }?.remotes.first { $0.address == address }?.verdict
    }

    /// The local ports the helper is told to block after a pass.
    private func blocked(_ l: Ledger, _ dir: URL) throws -> Set<Int> {
        l.refreshEnforcement()
        let text = try String(contentsOf: dir.appendingPathComponent("denied-ports.txt"), encoding: .utf8)
        return Set(text.split(whereSeparator: \.isNewline).compactMap { Int($0) })
    }

    func testDenyingOneProcessLeavesTheAppAlone() async throws {
        let (l, dir) = try ledger()
        l.setProcessPolicy(.deny, app: app, executable: updater)
        XCTAssertEqual(l.rules.processPolicy(app: app, executable: updater), .deny)
        await l.ingest(conns, [])
        XCTAssertEqual(verdict(l, servers[1]), .deny)
        XCTAssertEqual(verdict(l, servers[0]), .allow)
        XCTAssertEqual(try blocked(l, dir), [51002])
        XCTAssertFalse(l.deniedAppPaths.contains(app), "the app is not blocked as a whole")
    }

    func testAllowingOneProcessIsAnExceptionToTheAppsDeny() async throws {
        let (l, dir) = try ledger()
        l.setPolicy(.deny, for: app)
        XCTAssertTrue(l.deniedAppPaths.contains(app))
        l.setProcessPolicy(.allow, app: app, executable: updater)
        XCTAssertFalse(l.deniedAppPaths.contains(app), "blocking the whole app would cut the allowed process too")
        await l.ingest(conns, [])
        XCTAssertEqual(verdict(l, servers[1]), .allow)
        XCTAssertEqual(verdict(l, servers[0]), .deny)
        XCTAssertEqual(try blocked(l, dir), [51000, 51001])
        l.setProcessPolicy(nil, app: app, executable: updater)
        XCTAssertNil(l.rules.processPolicy(app: app, executable: updater))
        XCTAssertTrue(l.deniedAppPaths.contains(app), "without the exception the whole app is blocked again")
    }

    func testDenyingOneConnectionLeavesTheProcessesOtherConnections() async throws {
        let (l, dir) = try ledger()
        let quic = RulesModel.Endpoint(host: servers[2], address: servers[2], port: 443, proto: .udp)
        l.setConnectionPolicy(.deny, app: app, executable: main, quic)
        XCTAssertEqual(l.rules.connectionPolicy(app: app, executable: main, quic), .deny)
        let r = try XCTUnwrap(l.rules.ruleSet.rules.last)
        XCTAssertEqual(r.remoteAddress, servers[2]); XCTAssertNil(r.remoteHost, "an address has no name to keep")
        XCTAssertEqual(r.ports, 443...443); XCTAssertEqual(r.proto, .udp); XCTAssertEqual(r.listLevel, .connection)
        await l.ingest(conns, [])
        XCTAssertEqual(verdict(l, servers[2]), .deny)
        XCTAssertEqual(verdict(l, servers[0]), .allow)
        XCTAssertEqual(try blocked(l, dir), [51001])
    }

    func testANamedConnectionKeepsItsName() throws {
        let rules = RulesModel(directory: try tempDir())
        let e = RulesModel.Endpoint(host: "60.226.8.34.bc.googleusercontent.com", address: "34.8.226.60", port: 443, proto: .tcp)
        rules.setConnectionPolicy(.allow, app: app, executable: main, e)
        XCTAssertEqual(rules.ruleSet.rules.last?.remoteHost, "60.226.8.34.bc.googleusercontent.com")
        XCTAssertNil(rules.ruleSet.rules.last?.remoteAddress)
        rules.setConnectionPolicy(.deny, app: app, executable: main, e)
        XCTAssertEqual(rules.ruleSet.rules.filter { $0.listLevel == .connection }.count, 1, "the button replaces its rule")
        XCTAssertEqual(rules.connectionPolicy(app: app, executable: main, e), .deny)
        XCTAssertNil(rules.connectionPolicy(app: app, executable: updater, e), "another process's connection")
    }

    /// Several sockets of one process to the same server and port are one row: a rule that denies the row cuts
    /// every one of them, not only the first.
    func testEverySocketOfADeniedRowIsBlocked() async throws {
        let (l, dir) = try ledger()
        l.rules.ruleSet.rules = [Rule(verdict: .deny, processPath: app, remoteAddress: servers[0])]
        let twice = conns + [ObservedConnection(pid: 900, processPath: main, proto: .tcp, remoteAddress: servers[0], remotePort: 443, localPort: 51003, tcpState: "ESTABLISHED")]
        await l.ingest(twice, [])
        XCTAssertEqual(l.apps.first { $0.identity.ruleKey == app }?.remotes.filter { $0.address == servers[0] }.count, 1, "one row")
        XCTAssertEqual(try blocked(l, dir), [51000, 51003])
    }

    /// A rule for one system service in the `macOS` row now matches that service.
    func testARuleForOneSystemServiceMatchesIt() async throws {
        let (l, dir) = try ledger()
        l.rules.ruleSet.rules = [Rule(verdict: .deny, processPath: "/usr/libexec/demo-serviced")]
        await l.ingest([ObservedConnection(pid: 950, processPath: "/usr/libexec/demo-serviced", proto: .tcp, remoteAddress: servers[0], remotePort: 443, localPort: 52000, tcpState: "ESTABLISHED"),
                        ObservedConnection(pid: 951, processPath: "/usr/libexec/other-serviced", proto: .tcp, remoteAddress: servers[1], remotePort: 443, localPort: 52001, tcpState: "ESTABLISHED")], [])
        let system = try XCTUnwrap(l.apps.first { $0.identity.isSystem })
        XCTAssertEqual(system.remotes.first { $0.address == servers[0] }?.verdict, .deny)
        XCTAssertEqual(system.remotes.first { $0.address == servers[1] }?.verdict, .allow)
        XCTAssertEqual(try blocked(l, dir), [52000])
    }

    /// An open alert from a helper is answered by a ✗/✓ on that helper.
    func testAProcessButtonAnswersThatProcesssOpenAlert() throws {
        let (l, _) = try ledger()
        l.rules.ruleSet.silentVerdict = nil   // ask
        let a = ConnectionAlert(appID: app, appName: "Foo", host: servers[1], address: servers[1], port: 443, proto: "TCP", executable: updater)
        XCTAssertTrue(l.alerts.isStillPending(a))
        l.setProcessPolicy(.allow, app: app, executable: updater)
        XCTAssertFalse(l.alerts.isStillPending(a))
        let fromMain = ConnectionAlert(appID: app, appName: "Foo", host: servers[0], address: servers[0], port: 443, proto: "TCP", executable: main)
        XCTAssertTrue(l.alerts.isStillPending(fromMain), "the main process still asks")
    }
}
