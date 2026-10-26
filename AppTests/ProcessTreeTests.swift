import XCTest
import RatMonitor
@testable import Rat

/// The process tree (1.3.0): an app's main process holds its direct connections, every other process (helper, XPC
/// service; each macOS service) is a node with its own connections, PIDs and traffic, and a selection scopes the
/// connections shown on the map and in the inspector.
@MainActor
final class ProcessTreeTests: XCTestCase {
    private let chrome = "/Applications/Demo/Google Chrome.app"
    private var main: String { chrome + "/Contents/MacOS/Google Chrome" }
    private var helper: String { chrome + "/Contents/Frameworks/Google Chrome Helper.app/Contents/MacOS/Google Chrome Helper" }

    private func ledger() throws -> Ledger {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("rat-tree-\(UUID())")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        addTeardownBlock { try? FileManager.default.removeItem(at: dir) }
        return Ledger(directory: dir, helperInstalled: false)
    }

    private func conn(_ pid: Int32, _ path: String, _ address: String, _ port: Int, local: Int, proto: ObservedConnection.Proto = .tcp) -> ObservedConnection {
        ObservedConnection(pid: pid, processPath: path, proto: proto, remoteAddress: address, remotePort: port, localPort: local, tcpState: proto == .tcp ? "ESTABLISHED" : nil)
    }

    private func conns() -> [ObservedConnection] {
        [conn(401, main, "203.0.113.1", 443, local: 50001),
         conn(412, helper, "198.51.100.5", 443, local: 50002, proto: .udp),
         // Two sockets of another helper process to one server: one row, bytes added up.
         conn(413, helper, "198.51.100.6", 443, local: 50003),
         conn(413, helper, "198.51.100.6", 443, local: 50004)]
    }

    private func flows() -> [FlowCounter] {
        [FlowCounter(pid: 401, proto: .tcp, localPort: 50001, remoteAddress: "203.0.113.1", remotePort: 443, bytesIn: 1000, bytesOut: 100),
         FlowCounter(pid: 413, proto: .tcp, localPort: 50003, remoteAddress: "198.51.100.6", remotePort: 443, bytesIn: 300, bytesOut: 30),
         FlowCounter(pid: 413, proto: .tcp, localPort: 50004, remoteAddress: "198.51.100.6", remotePort: 443, bytesIn: 200, bytesOut: 20)]
    }

    func testAppTreeSplitsMainProcessFromHelpers() async throws {
        let l = try ledger()
        await l.ingest(conns(), [], flows: flows())
        let app = try XCTUnwrap(l.apps.first { $0.id == chrome })
        let tree = app.tree
        XCTAssertEqual(tree.direct.map(\.address), ["203.0.113.1"])
        XCTAssertEqual(tree.processes.map(\.name), ["Google Chrome Helper"])
        let node = try XCTUnwrap(tree.processes.first)
        XCTAssertEqual(node.pids, [412, 413])
        XCTAssertEqual(Set(node.remotes.map(\.address)), ["198.51.100.5", "198.51.100.6"])
        XCTAssertEqual(node.path, helper)
    }

    func testEndpointBytesComeFromTheirSockets() async throws {
        let l = try ledger()
        await l.ingest(conns(), [], flows: flows())
        let app = try XCTUnwrap(l.apps.first { $0.id == chrome })
        let direct = try XCTUnwrap(app.remotes.first { $0.address == "203.0.113.1" })
        XCTAssertEqual(direct.bytesIn, 1000); XCTAssertEqual(direct.bytesOut, 100)
        let shared = app.remotes.filter { $0.address == "198.51.100.6" }
        XCTAssertEqual(shared.count, 1, "two sockets to one server are one row")
        XCTAssertEqual(shared.first?.bytesIn, 500); XCTAssertEqual(shared.first?.bytesOut, 50)
        XCTAssertEqual(app.remotes.first { $0.address == "198.51.100.5" }?.bytesIn, 0, "no counter, no bytes")
    }

    func testProcessTrafficIsCountedPerExecutable() async throws {
        let l = try ledger()
        let first = [TrafficCounter(pid: 401, name: "Google Chrome", bytesIn: 1000, bytesOut: 10), TrafficCounter(pid: 413, name: "Google Chrome He", bytesIn: 5000, bytesOut: 50)]
        let second = [TrafficCounter(pid: 401, name: "Google Chrome", bytesIn: 1500, bytesOut: 20), TrafficCounter(pid: 413, name: "Google Chrome He", bytesIn: 9000, bytesOut: 90)]
        await l.ingest(conns(), first)
        await l.ingest(conns(), second)
        let app = try XCTUnwrap(l.apps.first { $0.id == chrome })
        XCTAssertEqual(app.processes["Google Chrome Helper"]?.totalIn, 4000)
        XCTAssertEqual(app.processes["Google Chrome"]?.totalIn, 500)
        XCTAssertEqual(app.totalIn, 4500, "the app's total is the sum of its processes")
    }

    func testSelectionScopesTheConnections() async throws {
        let l = try ledger()
        await l.ingest(conns(), [])
        let app = try XCTUnwrap(l.apps.first { $0.id == chrome })
        XCTAssertEqual(app.remotes(for: nil).count, 3)
        XCTAssertEqual(app.remotes(for: MonitorSelection(appID: chrome)).count, 3)
        XCTAssertEqual(app.remotes(for: MonitorSelection(appID: chrome, process: "Google Chrome")).map(\.address), ["203.0.113.1"])
        XCTAssertEqual(Set(app.remotes(for: MonitorSelection(appID: chrome, process: "Google Chrome Helper")).map(\.address)), ["198.51.100.5", "198.51.100.6"])
        let one = try XCTUnwrap(app.remotes.first { $0.address == "198.51.100.6" })
        XCTAssertEqual(app.remotes(for: MonitorSelection(appID: chrome, process: "Google Chrome Helper", remote: one.id)).map(\.id), [one.id])
    }

    func testExitedHelperKeepsItsTotalsButNoPIDs() async throws {
        let l = try ledger()
        await l.ingest(conns(), [TrafficCounter(pid: 413, name: "h", bytesIn: 10, bytesOut: 1)])
        await l.ingest(conns(), [TrafficCounter(pid: 413, name: "h", bytesIn: 20, bytesOut: 2)])
        await l.ingest(Array(conns().prefix(1)), [])
        let app = try XCTUnwrap(l.apps.first { $0.id == chrome })
        XCTAssertEqual(app.processes["Google Chrome Helper"]?.pids, [])
        XCTAssertEqual(app.processes["Google Chrome Helper"]?.totalIn, 10)
        XCTAssertTrue(app.tree.processes.isEmpty, "a helper with no process and no connections leaves the tree")
    }

    func testCommandLineToolsAndTheMacOSRow() async throws {
        let l = try ledger()
        await l.ingest([conn(760, "/opt/homebrew/opt/git/libexec/git-core/git-remote-https", "198.51.100.20", 443, local: 50010),
                        conn(90, "/usr/sbin/mDNSResponder", "192.0.2.53", 53, local: 5353, proto: .udp),
                        conn(95, "/usr/libexec/apsd", "192.0.2.80", 5223, local: 50011)], [])
        let git = try XCTUnwrap(l.apps.first { $0.identity.name == "git-remote-https" })
        XCTAssertEqual(git.tree.direct.count, 1, "a command-line tool is one executable: no sub-processes")
        XCTAssertTrue(git.tree.processes.isEmpty)
        let mac = try XCTUnwrap(l.apps.first { $0.identity.isSystem })
        XCTAssertTrue(mac.tree.direct.isEmpty, "the macOS row has no main process")
        XCTAssertEqual(mac.tree.processes.map(\.name).sorted(), ["apsd", "mDNSResponder"])
    }

    func testDemoDataHasHelpersServicesAndALaunchedTool() throws {
        let l = try ledger()
        l.installDemoData()
        let chrome = try XCTUnwrap(l.apps.first { $0.identity.name == "Google Chrome" })
        XCTAssertEqual(chrome.tree.processes.map(\.name), ["Google Chrome Helper"])
        XCTAssertEqual(chrome.tree.direct.count, 2)
        XCTAssertEqual(l.apps.first { $0.identity.isSystem }?.tree.processes.count, 2)
        XCTAssertEqual(l.apps.first { $0.identity.name == "git-remote-https" }?.launchedBy, "Warp (pid 700)")
    }
}
