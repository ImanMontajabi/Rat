import XCTest
import RatFilterCore
import RatMonitor
@testable import Rat

/// What Rat hands the root daemon in `deny-rules.json`, so it cuts one denied process or connection itself.
@MainActor
final class DaemonRulesAppTests: XCTestCase {
    let app = "/Applications/Foo.app"
    let main = "/Applications/Foo.app/Contents/MacOS/Foo"
    let updater = "/Applications/Foo.app/Contents/MacOS/Foo Updater"

    private func ledger() throws -> (Ledger, URL) {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("rat-daemon-rules-\(UUID())")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        addTeardownBlock { try? FileManager.default.removeItem(at: dir) }
        let names = HostNames(resolve: { $0 == "203.0.113.10" ? "api.example.com" : nil })
        for a in ["203.0.113.10", "203.0.113.11"] { _ = names.lookup(a) }
        let deadline = Date().addingTimeInterval(5)
        while !["203.0.113.10", "203.0.113.11"].allSatisfy({ names.lookup($0).settled }), Date() < deadline { RunLoop.current.run(until: Date().addingTimeInterval(0.02)) }
        return (Ledger(directory: dir, helperInstalled: true, names: names), dir)
    }

    private func written(_ dir: URL) throws -> DaemonRules {
        try XCTUnwrap(DaemonRules.decode(Data(contentsOf: dir.appendingPathComponent("deny-rules.json"))))
    }

    private var conns: [ObservedConnection] {
        [ObservedConnection(pid: 900, processPath: main, proto: .tcp, remoteAddress: "203.0.113.10", remotePort: 443, localPort: 51000, tcpState: "ESTABLISHED"),
         ObservedConnection(pid: 901, processPath: updater, proto: .tcp, remoteAddress: "203.0.113.11", remotePort: 443, localPort: 51002, tcpState: "ESTABLISHED")]
    }

    func testAProcessDenyIsHandedToTheDaemonWithTheNamesItNeeds() async throws {
        let (l, dir) = try ledger()
        await l.ingest(conns, [])
        l.setProcessPolicy(.deny, app: app, executable: updater)
        let d = try written(dir)
        XCTAssertTrue(d.hasProcessDenies)
        XCTAssertEqual(d.rules.filter { $0.listLevel == .process }.map(\.executable), [updater])
        XCTAssertEqual(d.names["203.0.113.10"], "api.example.com")
        XCTAssertEqual(d.names["203.0.113.11"], "", "judged without a name")
        // The daemon's judge agrees with Rat's pass for both connections.
        let j = SocketJudge(d)
        XCTAssertTrue(j.denies(app: app, executable: updater, address: "203.0.113.11", port: 443, proto: .tcp))
        XCTAssertFalse(j.denies(app: app, executable: main, address: "203.0.113.10", port: 443, proto: .tcp))
        XCTAssertFalse(l.deniedAppPaths.contains(app))
    }

    func testAConnectionDenyByNameIsCutForTheAddressesRatNamed() async throws {
        let (l, dir) = try ledger()
        await l.ingest(conns, [])
        l.setConnectionPolicy(.deny, app: app, executable: main, .init(host: "api.example.com", address: "203.0.113.10", port: 443, proto: .tcp))
        await l.ingest(conns, [])
        l.refreshEnforcement()
        let j = SocketJudge(try written(dir))
        XCTAssertTrue(j.denies(app: app, executable: main, address: "203.0.113.10", port: 443, proto: .tcp))
        XCTAssertFalse(j.denies(app: app, executable: updater, address: "203.0.113.11", port: 443, proto: .tcp))
        XCTAssertEqual(l.apps.first { $0.identity.ruleKey == app }?.remotes.first { $0.address == "203.0.113.10" }?.verdict, .deny, "Rat's pass agrees")
    }

    /// Names stay known after their connection closes, so the next connection to that server is judged at once.
    func testNamesOutliveTheirConnection() async throws {
        let (l, dir) = try ledger()
        await l.ingest(conns, [])
        l.setProcessPolicy(.deny, app: app, executable: updater)
        await l.ingest([], [])
        l.refreshEnforcement()
        XCTAssertEqual(try written(dir).names["203.0.113.10"], "api.example.com")
    }

    func testWithoutDenyRulesTheFileIsEmpty() async throws {
        let (l, dir) = try ledger()
        await l.ingest(conns, [])
        l.setProcessPolicy(.allow, app: app, executable: updater)
        XCTAssertEqual(try written(dir), DaemonRules(), "nothing for the daemon to read, and no names leave Rat")
        l.setProcessPolicy(.deny, app: app, executable: updater)
        XCTAssertTrue(try written(dir).hasProcessDenies)
        l.setProcessPolicy(nil, app: app, executable: updater)
        XCTAssertEqual(try written(dir), DaemonRules())
    }

    func testSessionRulesEndWithRat() async throws {
        let (l, dir) = try ledger()
        await l.ingest(conns, [])
        l.rules.ruleSet.rules.append(Rule(verdict: .deny, processPath: app, executable: updater, lifetime: .untilQuit))
        l.refreshEnforcement()
        XCTAssertTrue(try written(dir).hasProcessDenies)
        l.shutdown()
        XCTAssertFalse(try written(dir).hasProcessDenies)
    }

    /// The grouping moved to `ProcessGrouping.owner` so the daemon uses it too; the list's rule keys are unchanged.
    func testAppIdentityUsesTheSharedGrouping() {
        for p in ["/Applications/Foo.app/Contents/MacOS/Foo", "/Applications/Foo.app/Contents/PlugIns/X.appex/Contents/MacOS/X", "/usr/bin/curl",
                  "/opt/homebrew/bin/wget", "/Users/me/.local/share/claude/versions/2.1.308", "/Library/Application Support/Windscribe/bin/windscribewstunnel"] {
            XCTAssertEqual(AppIdentity.resolve(processPath: p).ruleKey, ProcessGrouping.owner(of: p, responsiblePath: { nil }).ruleKey, p)
        }
        XCTAssertEqual(AppIdentity.resolve(processPath: "/Applications/Foo.app/Contents/PlugIns/X.appex/Contents/MacOS/X").id, "/Applications/Foo.app#ext")
        XCTAssertEqual(AppIdentity.resolve(processPath: "/Users/me/.local/share/claude/versions/2.1.308").name, "claude")
    }
}
