import XCTest
import RatFilterCore
import RatMonitor
@testable import Rat

/// The three levels of the process list (app, process, connection) as the views use them: the ✗/✓ a row shows
/// (its own, or the one it follows), the rules about a row, the Rules window's Apps / Processes section and its
/// New Rule filled in from a row.
@MainActor
final class ThreeLevelRulesTests: XCTestCase {
    let app = "/Applications/Foo.app"
    let main = "/Applications/Foo.app/Contents/MacOS/Foo"
    let updater = "/Applications/Foo.app/Contents/MacOS/Foo Updater"
    let api = RulesModel.Endpoint(host: "api.example.com", address: "203.0.113.10", port: 443, proto: .tcp)

    private func tempDir() throws -> URL {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("rat-levels-\(UUID())")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        addTeardownBlock { try? FileManager.default.removeItem(at: dir) }
        return dir
    }

    private func model() throws -> RulesModel { RulesModel(directory: try tempDir()) }

    /// Reverse lookups that have answered (no names), so every connection is judged on the first pass.
    private func settledNames(_ addresses: [String]) -> HostNames {
        let names = HostNames(resolve: { _ in nil })
        for a in addresses { _ = names.lookup(a) }
        let deadline = Date().addingTimeInterval(5)
        while !addresses.allSatisfy({ names.lookup($0).settled }), Date() < deadline { RunLoop.current.run(until: Date().addingTimeInterval(0.02)) }
        return names
    }

    private var appRow: RulesModel.Target { .init(app: app) }
    private var updaterRow: RulesModel.Target { .init(app: app, executable: updater) }
    private var apiRow: RulesModel.Target { .init(app: app, executable: main, endpoint: api) }

    func testLevelsAndParents() {
        XCTAssertEqual(appRow.level, .app)
        XCTAssertEqual(updaterRow.level, .process)
        XCTAssertEqual(apiRow.level, .connection)
        XCTAssertEqual(apiRow.parent, RulesModel.Target(app: app, executable: main))
        XCTAssertEqual(updaterRow.parent, appRow)
        XCTAssertNil(appRow.parent)
    }

    /// A row without a choice of its own follows the nearest wider row: a connection its process, then its app.
    func testARowFollowsTheNearestWiderRow() throws {
        let rules = try model()
        XCTAssertEqual(rules.rowPolicy(apiRow), .init(own: nil, inherited: nil))
        rules.setPolicy(.deny, for: app)
        XCTAssertEqual(rules.rowPolicy(appRow), .init(own: .deny, inherited: nil))
        XCTAssertEqual(rules.rowPolicy(updaterRow), .init(own: nil, inherited: .deny))
        XCTAssertEqual(rules.rowPolicy(apiRow).effective, .deny, "through its process to the app")

        rules.setProcessPolicy(.allow, app: app, executable: main)
        XCTAssertEqual(rules.rowPolicy(apiRow), .init(own: nil, inherited: .allow), "the process is nearer than the app")
        XCTAssertEqual(rules.rowPolicy(updaterRow).inherited, .deny, "another process still follows the app")

        rules.setConnectionPolicy(.deny, app: app, executable: main, api)
        XCTAssertEqual(rules.rowPolicy(apiRow), .init(own: .deny, inherited: .allow))
        rules.setConnectionPolicy(nil, app: app, executable: main, api)
        XCTAssertNil(rules.rowPolicy(apiRow).own)
    }

    /// Rules from alerts are not a row's ✗/✓: a row follows only the list's own choices.
    func testRulesFromAlertsAreNotARowsChoice() throws {
        let rules = try model()
        rules.ruleSet.rules.append(Rule(verdict: .deny, processPath: app, remoteDomain: "example.com"))
        XCTAssertEqual(rules.rowPolicy(apiRow), .init(own: nil, inherited: nil))
    }

    /// The ledger's one setter writes the rule of the target's level.
    func testSettingATargetWritesThatLevelsRule() throws {
        let l = Ledger(directory: try tempDir(), helperInstalled: false)
        l.setPolicy(.deny, for: updaterRow)
        l.setPolicy(.allow, for: apiRow)
        l.setPolicy(.deny, for: appRow)
        let levels = l.rules.ruleSet.rules.compactMap(\.listLevel)
        XCTAssertEqual(levels.sorted(), [.app, .process, .connection])
        XCTAssertEqual(l.rules.processPolicy(app: app, executable: updater), .deny)
        XCTAssertEqual(l.rules.connectionPolicy(app: app, executable: main, api), .allow)
        XCTAssertEqual(l.rules.policy(for: app), .deny)
        l.setPolicy(nil, for: apiRow)
        XCTAssertNil(l.rules.connectionPolicy(app: app, executable: main, api))
        XCTAssertEqual(l.rules.ruleSet.rules.count, 2, "clearing removes only that row's rule")
    }

    func testTheRulesAboutEachLevel() throws {
        let rules = try model()
        let wholeApp = Rule(verdict: .allow, processPath: app, listLevel: .app)
        let updaterOnly = Rule(verdict: .deny, processPath: app, executable: updater, listLevel: .process)
        let helperPath = Rule(verdict: .deny, processPath: updater)
        let mainToAPI = Rule(verdict: .deny, processPath: app, executable: main, listLevel: .connection, remoteHost: "api.example.com", ports: 443...443, proto: .tcp)
        let anyToExample = Rule(verdict: .deny, remoteDomain: "example.com")
        let otherPort = Rule(verdict: .allow, processPath: app, ports: 8443...8443)
        var disabled = Rule(verdict: .deny, processPath: app, remoteHost: "api.example.com"); disabled.enabled = false
        let otherApp = Rule(verdict: .deny, processPath: "/Applications/Bar.app")
        rules.ruleSet.rules = [wholeApp, updaterOnly, helperPath, mainToAPI, anyToExample, otherPort, disabled, otherApp]

        let ids = { (t: RulesModel.Target) in Set(rules.rules(for: t).map(\.id)) }
        XCTAssertEqual(ids(appRow), Set([wholeApp, updaterOnly, helperPath, mainToAPI, otherPort, disabled].map(\.id)),
                       "rules naming the app or a program inside it; none for any process or another app")
        XCTAssertEqual(ids(updaterRow), Set([wholeApp, updaterOnly, helperPath, otherPort, disabled].map(\.id)),
                       "the app's rules for every process and the updater's own; not the main process's")
        XCTAssertEqual(ids(.init(app: app, executable: main)), Set([wholeApp, mainToAPI, otherPort, disabled].map(\.id)))
        XCTAssertEqual(ids(apiRow), Set([wholeApp, mainToAPI, anyToExample, disabled].map(\.id)),
                       "every rule that matches the connection, rules for any process and disabled ones too")
        XCTAssertEqual(rules.decidingRule(for: apiRow)?.id, mainToAPI.id, "the connection's ✗ decides it")
    }

    func testRulesOfAnotherProfileAreLeftOut() throws {
        let rules = try model()
        var elsewhere = Rule(verdict: .deny, processPath: app)
        elsewhere.profileID = UUID()
        rules.ruleSet.rules = [elsewhere]
        XCTAssertTrue(rules.rules(for: appRow).isEmpty)
    }

    func testNewRuleIsFilledInFromTheRow() throws {
        let rules = try model()
        let blank = rules.newRule(for: nil)
        XCTAssertNil(blank.processPath)
        XCTAssertEqual(blank.profileID, rules.ruleSet.activeProfileID)

        let forProcess = rules.newRule(for: updaterRow)
        XCTAssertEqual(forProcess.processPath, app)
        XCTAssertEqual(forProcess.executable, updater)
        XCTAssertNil(forProcess.remoteHost)

        let forConnection = rules.newRule(for: apiRow)
        XCTAssertEqual(forConnection.executable, main)
        XCTAssertEqual(forConnection.remoteHost, "api.example.com")
        XCTAssertNil(forConnection.remoteAddress)
        XCTAssertEqual(forConnection.ports, 443...443)
        XCTAssertEqual(forConnection.proto, .tcp)
        XCTAssertNil(forConnection.listLevel, "a Rules window rule, not a row's ✗/✓")

        let byAddress = rules.newRule(for: .init(app: app, executable: main, endpoint: .init(host: "203.0.113.9", address: "203.0.113.9", port: 53, proto: .udp)))
        XCTAssertEqual(byAddress.remoteAddress, "203.0.113.9")
        XCTAssertNil(byAddress.remoteHost)
        XCTAssertEqual(byAddress.proto, .udp)
    }

    /// Each row of the list names its target: the app, a process by its executable, a connection of that process.
    /// A connection inside the local network has none (Rat's pass does not judge it, so a rule could not hold).
    func testTheListsRowsNameTheirTargets() async throws {
        let l = Ledger(directory: try tempDir(), helperInstalled: false, names: settledNames(["203.0.113.10", "203.0.113.11"]))
        await l.ingest([ObservedConnection(pid: 900, processPath: main, proto: .tcp, remoteAddress: "203.0.113.10", remotePort: 443, localPort: 51000, tcpState: "ESTABLISHED"),
                        ObservedConnection(pid: 901, processPath: updater, proto: .udp, remoteAddress: "203.0.113.11", remotePort: 443, localPort: 51001, tcpState: nil),
                        ObservedConnection(pid: 900, processPath: main, proto: .tcp, remoteAddress: "192.168.1.20", remotePort: 8080, localPort: 51002, tcpState: "ESTABLISHED")], [])
        let entry = try XCTUnwrap(l.apps.first { $0.identity.ruleKey == app })
        XCTAssertEqual(entry.ruleTarget(process: nil), RulesModel.Target(app: app))
        XCTAssertEqual(entry.ruleTarget(process: "Foo Updater"), RulesModel.Target(app: app, executable: updater))
        XCTAssertNil(entry.ruleTarget(process: "Never Seen"), "an executable that was never seen")

        let remote = { (a: String) in try XCTUnwrap(entry.remotes.first { $0.address == a }) }
        let mainConn = try XCTUnwrap(entry.ruleTarget(process: entry.mainProcess, remote: remote("203.0.113.10")))
        XCTAssertEqual(mainConn.executable, main)
        XCTAssertEqual(mainConn.endpoint, .init(host: "203.0.113.10", address: "203.0.113.10", port: 443, proto: .tcp))
        XCTAssertEqual(entry.ruleTarget(process: "Foo Updater", remote: try remote("203.0.113.11"))?.endpoint?.proto, .udp)
        XCTAssertNil(entry.ruleTarget(process: entry.mainProcess, remote: try remote("192.168.1.20")), "local network")

        let selected = MonitorSelection(appID: entry.id, process: "Foo Updater", remote: try remote("203.0.113.11").id)
        XCTAssertEqual(entry.ruleTarget(for: selected)?.executable, updater)
    }

    /// A ✗ on a connection row is enforced like the Phase 2 setter: the next pass denies only that connection.
    func testAConnectionRowsDenyIsJudgedOnTheNextPass() async throws {
        let l = Ledger(directory: try tempDir(), helperInstalled: true, names: settledNames(["203.0.113.10", "203.0.113.12"]))
        let conns = [ObservedConnection(pid: 900, processPath: main, proto: .tcp, remoteAddress: "203.0.113.10", remotePort: 443, localPort: 51000, tcpState: "ESTABLISHED"),
                     ObservedConnection(pid: 900, processPath: main, proto: .tcp, remoteAddress: "203.0.113.12", remotePort: 443, localPort: 51003, tcpState: "ESTABLISHED")]
        await l.ingest(conns, [])
        let entry = try XCTUnwrap(l.apps.first { $0.identity.ruleKey == app })
        let r = try XCTUnwrap(entry.remotes.first { $0.address == "203.0.113.10" })
        l.setPolicy(.deny, for: try XCTUnwrap(entry.ruleTarget(process: entry.mainProcess, remote: r)))
        await l.ingest(conns, [])
        let after = try XCTUnwrap(l.apps.first { $0.identity.ruleKey == app })
        XCTAssertEqual(after.remotes.first { $0.address == "203.0.113.10" }?.verdict, .deny)
        XCTAssertNotEqual(after.remotes.first { $0.address == "203.0.113.12" }?.verdict, .deny)
        XCTAssertTrue(l.deniedAppPaths.isEmpty, "not denied as a whole app")
    }

    /// A process with a TCP and a UDP (QUIC) connection to one server and port has a row for each. They used to be
    /// one row, showing whichever socket the kernel listed first: a ✗ made a rule for that protocol, and when the
    /// order changed on the next pass the row showed the other one, so the ✗ looked as if the click was lost.
    func testTCPAndUDPToOneServerAreTwoRowsWithTheirOwnChoice() async throws {
        let dir = try tempDir()
        let l = Ledger(directory: dir, helperInstalled: true, names: settledNames(["203.0.113.10"]))
        let tcp = ObservedConnection(pid: 900, processPath: main, proto: .tcp, remoteAddress: "203.0.113.10", remotePort: 443, localPort: 51000, tcpState: "ESTABLISHED")
        let udp = ObservedConnection(pid: 900, processPath: main, proto: .udp, remoteAddress: "203.0.113.10", remotePort: 443, localPort: 51001, tcpState: nil)
        await l.ingest([udp, tcp], [])
        var entry = try XCTUnwrap(l.apps.first { $0.identity.ruleKey == app })
        XCTAssertEqual(entry.remotes.map(\.proto).sorted(), ["TCP", "UDP"])
        XCTAssertEqual(Set(entry.remotes.map(\.id)).count, 2, "each row has an identity of its own")
        let tcpRow = try XCTUnwrap(entry.remotes.first { $0.proto == "TCP" })
        let target = try XCTUnwrap(entry.ruleTarget(process: entry.mainProcess, remote: tcpRow))
        XCTAssertEqual(target.endpoint?.proto, .tcp)
        l.setPolicy(.deny, for: target)

        // The kernel lists the sockets the other way round: the TCP row keeps its ✗, the UDP row has none.
        await l.ingest([tcp, udp], [])
        entry = try XCTUnwrap(l.apps.first { $0.identity.ruleKey == app })
        for r in entry.remotes {
            let t = try XCTUnwrap(entry.ruleTarget(process: entry.mainProcess, remote: r))
            XCTAssertEqual(l.rules.rowPolicy(t).own, r.proto == "TCP" ? .deny : nil, r.proto)
            XCTAssertEqual(r.verdict == .deny, r.proto == "TCP", r.proto)
        }
        l.refreshEnforcement()
        let ports = try String(contentsOf: dir.appendingPathComponent("denied-ports.txt"), encoding: .utf8)
        XCTAssertEqual(ports, "51000\n", "only the TCP socket is cut")
    }

    func testTheRulesWindowListsTheAppsAndProcessesRulesName() {
        let rules = [Rule(verdict: .deny, processPath: app, executable: updater, listLevel: .process),
                     Rule(verdict: .allow, processPath: app),
                     Rule(verdict: .deny, processPath: "/usr/sbin/mDNSResponder"),
                     Rule(verdict: .deny, remoteDomain: "ads.example")]
        let rows = RulesWindow.ruleApps(rules, pinned: nil)
        XCTAssertEqual(rows.map(\.name), ["Foo", "mDNSResponder"], "by name; a rule for any process names no app")
        XCTAssertEqual(rows.first?.processes, [updater])
        XCTAssertNil(rows.first?.connection)

        let pinned = RulesWindow.ruleApps(rules, pinned: .init(app: "/Applications/Bar.app", executable: "/Applications/Bar.app/Contents/MacOS/Bar", endpoint: api))
        let bar = pinned.first { $0.app == "/Applications/Bar.app" }
        XCTAssertEqual(bar?.processes, ["/Applications/Bar.app/Contents/MacOS/Bar"], "the row the inspector opened on, before it has rules")
        XCTAssertEqual(bar?.connection?.endpoint, api)
        XCTAssertEqual(RulesWindow.connectionName(.init(app: app, executable: main, endpoint: api)), "api.example.com : 443 (TCP)")
        XCTAssertEqual(RulesWindow.displayName("macOS"), "macOS")
    }

    /// A row's rule saved under one name of a cryptex program is still the row's choice under the other.
    func testARowsRuleSurvivesTheOtherCryptexName() throws {
        let rules = try model()
        let safari = "/System/Volumes/Preboot/Cryptexes/App/System/Applications/Safari.app"
        let started = "/System/Library/PrivateFrameworks/SafariShared.framework/Versions/A/XPCServices/com.apple.Safari.SearchHelper.xpc/Contents/MacOS/com.apple.Safari.SearchHelper"
        rules.setProcessPolicy(.deny, app: safari, executable: started)
        XCTAssertEqual(rules.processPolicy(app: safari, executable: "/System/Volumes/Preboot/Cryptexes/Incoming/OS" + started), .deny)
        rules.setProcessPolicy(nil, app: safari, executable: "/System/Volumes/Preboot/Cryptexes/Incoming/OS" + started)
        XCTAssertTrue(rules.ruleSet.rules.isEmpty, "clearing it under the other name removes it")
    }
}
