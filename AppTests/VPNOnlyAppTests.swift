import XCTest
import RatFilterCore
import RatMonitor
@testable import Rat

/// "Only through a VPN" (#45) in the app: the inspector's switch makes one rule per app or process, Rat's pass cuts
/// each socket that leaves outside the tunnel (sockets to one server on both sides of it are judged apart), and the
/// daemon file carries it where a helper before 1.6.0 does not read it.
@MainActor
final class VPNOnlyAppTests: XCTestCase {
    let app = "/Applications/Foo.app"
    let main = "/Applications/Foo.app/Contents/MacOS/Foo"
    let updater = "/Applications/Foo.app/Contents/MacOS/Foo Updater"

    private func tempDir() throws -> URL {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("rat-vpnonly-\(UUID())")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        addTeardownBlock { try? FileManager.default.removeItem(at: dir) }
        return dir
    }

    private func settledNames(_ addresses: [String]) -> HostNames {
        let names = HostNames(resolve: { _ in nil })
        for a in addresses { _ = names.lookup(a) }
        let deadline = Date().addingTimeInterval(5)
        while !addresses.allSatisfy({ names.lookup($0).settled }), Date() < deadline { RunLoop.current.run(until: Date().addingTimeInterval(0.02)) }
        return names
    }

    func testTheSwitchMakesOneRulePerAppOrProcess() throws {
        let m = RulesModel(directory: try tempDir())
        let appRow = RulesModel.Target(app: app), updaterRow = RulesModel.Target(app: app, executable: updater)
        XCTAssertFalse(m.vpnOnly(appRow))
        m.setVPNOnly(true, for: appRow)
        m.setVPNOnly(true, for: appRow)
        XCTAssertEqual(m.ruleSet.rules.filter(\.requireVPN).count, 1, "switching it on twice makes one rule")
        let r = try XCTUnwrap(m.ruleSet.rules.first)
        XCTAssertEqual(r.verdict, .deny); XCTAssertEqual(r.processPath, app); XCTAssertNil(r.executable)
        XCTAssertTrue(m.vpnOnly(appRow))
        XCTAssertFalse(m.vpnOnly(updaterRow), "the process has none of its own")
        XCTAssertTrue(m.vpnOnlyInherited(updaterRow), "it follows the app's")
        XCTAssertNil(m.policy(for: app), "the app's ✗/✓ stays unset")

        m.setVPNOnly(true, for: updaterRow)
        XCTAssertEqual(m.ruleSet.rules.filter(\.requireVPN).compactMap(\.executable), [updater])
        m.setVPNOnly(false, for: appRow)
        XCTAssertFalse(m.vpnOnly(appRow))
        XCTAssertTrue(m.vpnOnly(updaterRow), "the process's own stays")
        m.setVPNOnly(true, for: RulesModel.Target(app: app, executable: main, endpoint: .init(host: nil, address: "203.0.113.5", port: 443, proto: .tcp)))
        XCTAssertEqual(m.ruleSet.rules.count, 1, "never for one connection")

        // The rules about a connection list it, whichever side of the tunnel the connection is on.
        let listed = m.rules(for: RulesModel.Target(app: app, executable: updater, endpoint: .init(host: nil, address: "203.0.113.5", port: 443, proto: .tcp)))
        XCTAssertEqual(listed.map(\.requireVPN), [true])
    }

    func testRatsPassCutsOnlyTheSocketsOutsideTheTunnel() async throws {
        let dir = try tempDir()
        let l = Ledger(directory: dir, helperInstalled: true, names: settledNames(["203.0.113.8", "198.51.100.3"]))
        l.routes.set(tunnelAddresses: ["100.127.80.66": "utun420"], tunnelNames: ["utun420": "Windscribe"], proxies: [])
        func tcp(_ remote: String, local: String, port: Int) -> ObservedConnection {
            ObservedConnection(pid: 900, processPath: main, proto: .tcp, remoteAddress: remote, remotePort: 443, localPort: port, tcpState: "ESTABLISHED", localAddress: local)
        }
        let conns = [tcp("203.0.113.8", local: "100.127.80.66", port: 51000),   // through the VPN
                     tcp("203.0.113.8", local: "192.168.178.39", port: 51001),  // the same server, opened before the VPN came up
                     tcp("198.51.100.3", local: "192.168.178.39", port: 51002),
                     tcp("192.168.178.1", local: "192.168.178.39", port: 51003)] // the router
        l.setPolicy(.allow, for: app)
        l.setVPNOnly(true, for: RulesModel.Target(app: app))
        await l.ingest(conns, [])
        l.refreshEnforcement()
        let entry = try XCTUnwrap(l.apps.first { $0.identity.ruleKey == app })
        XCTAssertEqual(entry.remotes.first { $0.address == "203.0.113.8" }?.verdict, .allow, "the row's first socket goes through the VPN")
        XCTAssertEqual(entry.remotes.first { $0.address == "198.51.100.3" }?.verdict, .deny, "the app's ✓ does not lift it")
        let ports = try String(contentsOf: dir.appendingPathComponent("denied-ports.txt"), encoding: .utf8)
        XCTAssertEqual(ports, "51001\n51002\n", "the sockets outside the tunnel, not the router's")
        XCTAssertTrue(l.deniedAppPaths.isEmpty, "never the whole app")

        // The daemon gets it apart from the rules a helper before 1.6.0 reads.
        let d = try XCTUnwrap(DaemonRules.decode(Data(contentsOf: dir.appendingPathComponent("deny-rules.json"))))
        XCTAssertEqual(d.conditionalRules.map(\.requireVPN), [true])
        XCTAssertFalse(d.rules.contains(where: \.requireVPN))
        XCTAssertTrue(SocketJudge(d).needsRoute)

        // Off again: nothing is cut.
        l.setVPNOnly(false, for: RulesModel.Target(app: app))
        await l.ingest(conns, [])
        l.refreshEnforcement()
        XCTAssertEqual(try String(contentsOf: dir.appendingPathComponent("denied-ports.txt"), encoding: .utf8), "")
    }

    func testWithoutAVPNEverythingOutsideTheLocalNetworkIsCut() async throws {
        let dir = try tempDir()
        let l = Ledger(directory: dir, helperInstalled: true, names: settledNames(["203.0.113.8"]))
        l.routes.set(tunnelAddresses: [:], tunnelNames: [:], proxies: [])
        l.setVPNOnly(true, for: RulesModel.Target(app: app, executable: updater))
        let conns = [ObservedConnection(pid: 900, processPath: main, proto: .tcp, remoteAddress: "203.0.113.8", remotePort: 443, localPort: 51000, tcpState: "ESTABLISHED", localAddress: "192.168.178.39"),
                     ObservedConnection(pid: 901, processPath: updater, proto: .tcp, remoteAddress: "203.0.113.8", remotePort: 443, localPort: 51001, tcpState: "ESTABLISHED", localAddress: "192.168.178.39")]
        await l.ingest(conns, [])
        l.refreshEnforcement()
        XCTAssertEqual(try String(contentsOf: dir.appendingPathComponent("denied-ports.txt"), encoding: .utf8), "51001\n", "only the updater has it")
    }
}
