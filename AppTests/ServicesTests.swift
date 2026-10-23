import XCTest
import RatFilterCore
@testable import Rat

@MainActor
final class ServicesTests: XCTestCase {
    private func tempDir() -> URL {
        let d = FileManager.default.temporaryDirectory.appendingPathComponent("rat-svc-\(UUID())")
        try? FileManager.default.createDirectory(at: d, withIntermediateDirectories: true)
        return d
    }

    func testStateStoreIsTolerantOfOlderFiles() throws {
        let dir = tempDir()
        // Before 1.0.4 the state held the server addresses of denied apps; they are dropped on the next save.
        try #"{"apps":[],"blocked":{"x":["1.2.3.4"]},"denied":{"x":[{"address":"1.1.1.1","host":"h","port":443,"proto":"TCP"}]},"buckets":[]}"#.write(to: dir.appendingPathComponent("state.json"), atomically: true, encoding: .utf8)
        let store = StateStore.standard(base: dir)
        XCTAssertTrue(store.load().apps.isEmpty)
        store.save(store.load())
        XCTAssertFalse(try String(contentsOf: dir.appendingPathComponent("state.json"), encoding: .utf8).contains("1.1.1.1"))
    }

    func testStateStoreRoundTrip() {
        let store = StateStore.standard(base: tempDir())
        let app = PersistedApp(id: "a", name: "A", bundlePath: nil, isSystem: false, totalIn: 5, totalOut: 6, lastActive: Date(timeIntervalSince1970: 1_700_000_000))
        store.save(PersistedState(apps: [app], buckets: []))
        let back = store.load()
        XCTAssertEqual(back.apps.first?.totalIn, 5)
    }

    func testStorageIsConfinedToOneDirectory() {
        let dir = tempDir()
        let ledger = Ledger(directory: dir)
        ledger.rules.setPolicy(.deny, for: "/Applications/Foo.app")
        ledger.save()
        let files = (try? FileManager.default.contentsOfDirectory(atPath: dir.path)) ?? []
        XCTAssertTrue(Set(files).isSuperset(of: ["state.json", "rules.json"]), "\(files)")
    }

    func testEnforcerNeverTouchesFirewallWithoutHelper() {
        let dir = tempDir()
        // A blocklist left by an earlier version is removed on start.
        try? "1.1.1.1\n8.8.8.8\n".write(to: dir.appendingPathComponent("blocklist.txt"), atomically: true, encoding: .utf8)
        let e = Enforcer(supportDirectory: dir, helperInstalled: false, statusPath: dir.appendingPathComponent("status.json").path)
        XCTAssertFalse(FileManager.default.fileExists(atPath: dir.appendingPathComponent("blocklist.txt").path))
        e.syncApps(["/Applications/Foo.app"]); e.syncPorts([50000])
        XCTAssertFalse(FileManager.default.fileExists(atPath: dir.appendingPathComponent("denied-apps.txt").path), "nothing is written without the helper")
        XCTAssertNil(e.systemSnapshotText())
        // With the helper present and auto-apply on, the daemon is fed apps and ports, and never addresses.
        let installed = Enforcer(supportDirectory: dir, helperInstalled: true, statusPath: dir.appendingPathComponent("status.json").path)
        installed.syncApps(["/Applications/Foo.app", "/Applications/Bar.app"]); installed.syncPorts([50001, 50000])
        XCTAssertEqual(try? String(contentsOf: dir.appendingPathComponent("denied-apps.txt"), encoding: .utf8), "/Applications/Bar.app\n/Applications/Foo.app\n")
        XCTAssertEqual(try? String(contentsOf: dir.appendingPathComponent("denied-ports.txt"), encoding: .utf8), "50000\n50001\n")
        XCTAssertFalse(FileManager.default.fileExists(atPath: dir.appendingPathComponent("blocklist.txt").path))
        // A deleted (or edited) file is rewritten on the next pass: the enforcer compares with the file, not a cache.
        try? FileManager.default.removeItem(at: dir.appendingPathComponent("denied-apps.txt"))
        installed.syncApps(["/Applications/Foo.app", "/Applications/Bar.app"])
        XCTAssertEqual(try? String(contentsOf: dir.appendingPathComponent("denied-apps.txt"), encoding: .utf8), "/Applications/Bar.app\n/Applications/Foo.app\n")
        installed.syncApps([])
        XCTAssertEqual(try? String(contentsOf: dir.appendingPathComponent("denied-apps.txt"), encoding: .utf8), "", "removing the deny unblocks the app")
    }

    /// Deny hands the app to the helper, which blocks its ports; no server address is ever written anywhere.
    func testDenyNeverBlocksServerAddresses() throws {
        let dir = tempDir()
        let ledger = Ledger(directory: dir, helperInstalled: true)
        ledger.installDemoData()
        let chrome = ledger.apps.first { $0.identity.name == "Google Chrome" }!
        ledger.setPolicy(.deny, for: chrome.id)
        XCTAssertTrue(ledger.deniedAppPaths.contains(chrome.identity.ruleKey))
        XCTAssertEqual(try String(contentsOf: dir.appendingPathComponent("denied-apps.txt"), encoding: .utf8), chrome.identity.ruleKey + "\n")
        XCTAssertFalse(FileManager.default.fileExists(atPath: dir.appendingPathComponent("blocklist.txt").path))
        ledger.setPolicy(nil, for: chrome.id)
        XCTAssertFalse(ledger.deniedAppPaths.contains(chrome.identity.ruleKey), "removing the rule unblocks the app")
    }

    func testAlertCenterDedupesAndAnswers() {
        let dir = tempDir()
        let rules = RulesModel(directory: dir)
        rules.silentMode = .off
        var decisions: [Verdict] = []
        let center = AlertCenter(rules: rules) { _, v in decisions.append(v) }
        let a = ConnectionAlert(appID: "/Applications/Foo.app", appName: "Foo", host: "a.example.com", address: "203.0.113.1", port: 443, proto: "TCP")
        let sameDomain = ConnectionAlert(appID: "/Applications/Foo.app", appName: "Foo", host: "b.example.com", address: "203.0.113.2", port: 443, proto: "TCP")
        center.report(a)
        center.report(sameDomain)
        XCTAssertEqual(center.pendingCount, 1, "same app and domain alert once")
        center.answer(a, verdict: .deny, scope: .domain, lifetime: .forever)
        XCTAssertEqual(decisions, [.deny])
        XCTAssertEqual(rules.ruleSet.rules.first?.remoteDomain, "example.com")
        XCTAssertEqual(center.pendingCount, 0)
    }

    func testMenuBarRateFormatting() {
        XCTAssertEqual(MenuBarController.rate(0), "0 bytes/s")
        XCTAssertTrue(MenuBarController.rate(1_500_000).hasSuffix("/s"))
    }

    func testGeoServiceOfflineLookup() throws {
        guard ProcessInfo.processInfo.environment["RAT_GEOIP_DB"] != nil || Bundle.main.url(forResource: "dbip-city-lite", withExtension: "mmdb", subdirectory: "Vendor") != nil else {
            throw XCTSkip("no GeoIP database available")
        }
        let g = GeoService()
        XCTAssertTrue(g.available)
        XCTAssertEqual(g.lookup("8.8.8.8")?.country, "United States")
        XCTAssertNil(g.lookup("10.0.0.1"))
        XCTAssertNotNil(GeoService.localPoint())
    }

    func testBundledGeoDatabaseShipsInVendorFolder() throws {
        let url = Bundle.main.url(forResource: "dbip-city-lite", withExtension: "mmdb", subdirectory: "Vendor")
        XCTAssertNotNil(url, "Contents/Resources/Vendor/dbip-city-lite.mmdb must be bundled; run scripts/fetch-geoip.sh")
    }
}
