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
        // v0.2 wrote `blocked` and no `denied`.
        try #"{"apps":[],"blocked":{"x":["1.2.3.4"]},"buckets":[]}"#.write(to: dir.appendingPathComponent("state.json"), atomically: true, encoding: .utf8)
        let s = StateStore.standard(base: dir).load()
        XCTAssertTrue(s.denied.isEmpty)
    }

    func testStateStoreRoundTrip() {
        let store = StateStore.standard(base: tempDir())
        let app = PersistedApp(id: "a", name: "A", bundlePath: nil, isSystem: false, totalIn: 5, totalOut: 6, lastActive: Date(timeIntervalSince1970: 1_700_000_000))
        store.save(PersistedState(apps: [app], denied: ["a": [DeniedEntry(address: "1.1.1.1", host: "h", port: 443, proto: "TCP")]], buckets: []))
        let back = store.load()
        XCTAssertEqual(back.apps.first?.totalIn, 5)
        XCTAssertEqual(back.denied["a"]?.first?.address, "1.1.1.1")
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
        let e = Enforcer(supportDirectory: dir, helperInstalled: false, autoApply: true)
        e.sync(["1.2.3.4"])
        XCTAssertFalse(FileManager.default.fileExists(atPath: dir.appendingPathComponent("blocklist.txt").path))
        XCTAssertTrue(e.needsApply(for: ["1.2.3.4"]))
        XCTAssertFalse(e.needsApply(for: []))
        XCTAssertNil(e.systemSnapshotText())
        // With the helper present and auto-apply on, syncing writes the list the daemon watches.
        let installed = Enforcer(supportDirectory: dir, helperInstalled: true, autoApply: true)
        installed.sync(["1.2.3.4", "5.6.7.8"])
        XCTAssertEqual(try? String(contentsOf: dir.appendingPathComponent("blocklist.txt"), encoding: .utf8), "1.2.3.4\n5.6.7.8\n")
        XCTAssertFalse(installed.needsApply(for: ["1.2.3.4", "5.6.7.8"]))
    }

    func testDeniedAppEntersWantedBlocklist() {
        let ledger = Ledger(directory: tempDir(), helperInstalled: false)
        ledger.installDemoData()
        let chrome = ledger.apps.first { $0.identity.name == "Google Chrome" }!
        XCTAssertTrue(ledger.wantedBlocklist.isEmpty)
        ledger.setPolicy(.deny, for: chrome.id)
        XCTAssertEqual(ledger.wantedBlocklist, Set(chrome.remotes.map(\.address)))
        XCTAssertEqual(ledger.blockedAddresses(for: chrome.id), chrome.remotes.count)
        ledger.setPolicy(nil, for: chrome.id)
        XCTAssertTrue(ledger.wantedBlocklist.isEmpty, "removing the rule shrinks the blocklist")
    }

    /// With the enforcer running, a denied app is cut by its ports and its servers stay reachable for other apps.
    func testDeniedAppDoesNotBlockItsServersGloballyWithEnforcer() {
        let ledger = Ledger(directory: tempDir(), helperInstalled: true)
        ledger.installDemoData()
        let chrome = ledger.apps.first { $0.identity.name == "Google Chrome" }!
        ledger.setPolicy(.deny, for: chrome.id)
        XCTAssertTrue(ledger.deniedAppPaths.contains(chrome.identity.ruleKey))
        XCTAssertTrue(ledger.wantedBlocklist.isEmpty)
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
