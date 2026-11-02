import XCTest
import AppKit
import RatMonitor
@testable import Rat

/// A Safari web app (Add to Dock) shows as itself: the name the user gave it and its own icon, with Safari's
/// "Web App" program as its main process and WebKit.Networking under it, not as one "Web App" for all of them.
@MainActor
final class SafariWebAppIdentityTests: XCTestCase {
    /// A web app's bundle as Safari writes it: an Info.plist, an icon, no program.
    private func webApp(file: String, info: [String: Any]) throws -> String {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("rat-webapp-\(UUID())")
        let contents = dir.appendingPathComponent(file).appendingPathComponent("Contents")
        try FileManager.default.createDirectory(at: contents.appendingPathComponent("Resources"), withIntermediateDirectories: true)
        addTeardownBlock { try? FileManager.default.removeItem(at: dir) }
        let data = try PropertyListSerialization.data(fromPropertyList: info, format: .xml, options: 0)
        try data.write(to: contents.appendingPathComponent("Info.plist"))
        return dir.appendingPathComponent(file).path
    }

    func testAWebAppIsNamedByItsInfoPlistAndRunsAsWebApp() throws {
        let path = try webApp(file: "Feed 2.app", info: ["CFBundleIdentifier": "com.apple.Safari.WebApp.5E77154E-E087-4E17-A38E-0A77B5B8757D",
                                                         "CFBundleName": "Feed", "CFBundlePackageType": "AAPL"])
        let id = AppIdentity.resolve(processPath: path)
        XCTAssertEqual(id.name, "Feed", "the name chosen in Add to Dock, not the numbered file name")
        XCTAssertEqual(id.ruleKey, path); XCTAssertEqual(id.bundlePath, path); XCTAssertFalse(id.isSystem)
        XCTAssertEqual(id.mainProcessName, "Web App", "Safari's program runs it")
        XCTAssertEqual(id.ruleKey, ProcessGrouping.owner(of: path, responsiblePath: { nil }).ruleKey, "the daemon names the same app")
        // A display name wins over the bundle name.
        let shown = try webApp(file: "Mail.app", info: ["CFBundleIdentifier": "com.apple.Safari.WebApp.1", "CFBundleName": "Mail", "CFBundleDisplayName": "Google Mail"])
        XCTAssertEqual(AppIdentity.resolve(processPath: shown).name, "Google Mail")
    }

    func testAnOrdinaryBundleKeepsTheNameFinderShows() throws {
        let path = try webApp(file: "Tool.app", info: ["CFBundleIdentifier": "com.example.tool", "CFBundleName": "Something Else"])
        XCTAssertEqual(AppIdentity.resolve(processPath: path).name, "Tool")
        XCTAssertNil(AppIdentity.webAppName(path))
        // The program that runs web apps, when its web app cannot be read, is the one "Web App" as before.
        let host = "/System/Volumes/Preboot/Cryptexes/App/System/Library/CoreServices/Web App.app/Contents/MacOS/Web App"
        XCTAssertEqual(AppIdentity.resolve(processPath: host).ruleKey, "/System/Volumes/Preboot/Cryptexes/App/System/Library/CoreServices/Web App.app")
    }

    /// On this Mac, while a web app runs: the processes Rat sees (the host, its WebKit.Networking) are that web app,
    /// with its name and its own icon, and the daemon groups them the same way.
    func testLiveWebAppProcessesShowTheWebApp() throws {
        let pids = ConnectionSampler.allPIDs()
        guard let host = pids.first(where: { SafariWebApp.isHost(ConnectionSampler.path(of: $0)) }),
              let bundle = SafariWebApp.bundle(pid: host) else { throw XCTSkip("no Safari web app is running") }
        let name = try XCTUnwrap(AppIdentity.webAppName(bundle))
        let networking = pids.filter { ProcessGrouping.responsiblePID(of: $0) == host && ConnectionSampler.path(of: $0).hasSuffix("/com.apple.WebKit.Networking") }
        XCTAssertFalse(networking.isEmpty, "the web app's WebKit.Networking")
        for pid in [host] + networking {
            let path = ConnectionSampler.path(of: pid)
            let id = AppIdentity.resolve(processPath: path, pid: pid)
            XCTAssertEqual(id.ruleKey, bundle, path); XCTAssertEqual(id.name, name, path)
            XCTAssertEqual(id.ruleKey, ProcessGrouping.owner(of: path, responsiblePath: { ProcessGrouping.responsiblePath(of: pid) },
                                                             webApp: { SafariWebApp.bundle(pid: pid, path: path) }).ruleKey)
        }
        let generic = NSWorkspace.shared.icon(forFile: "/System/Library/CoreServices/Web App.app").tiffRepresentation
        AppIdentity.iconCache[bundle] = nil
        XCTAssertNotEqual(AppIdentity.resolve(processPath: bundle).icon.tiffRepresentation, generic, "its own icon, not the generic one")
    }
}
