import XCTest
import MapKit
import RatFilterCore
@testable import Rat

@MainActor
final class Release101Tests: XCTestCase {
    private func tempDir() -> URL {
        let d = FileManager.default.temporaryDirectory.appendingPathComponent("rat-101-\(UUID())")
        try? FileManager.default.createDirectory(at: d, withIntermediateDirectories: true)
        return d
    }

    // MARK: silent mode default and alert spam

    func testNewInstallDefaultsToSilentAllow() {
        let m = RulesModel(directory: tempDir())
        XCTAssertEqual(m.silentMode, .allow)
        let c = Connection(process: ProcessIdentity(path: "/Applications/Foo.app"), host: "a.com", address: "203.0.113.5", port: 443)
        XCTAssertEqual(m.engine.evaluate(c), .allow)
    }

    func testAppWithWholeAppPolicyNeverRaisesAnAlert() {
        let ledger = Ledger(directory: tempDir())
        ledger.rules.silentMode = .off
        let center = ledger.alerts
        let chrome = ConnectionAlert(appID: "/Applications/Google Chrome.app", appName: "Google Chrome", host: "2607:6bc0::10", address: "2607:6bc0::10", port: 443, proto: "TCP")
        center.report(chrome)
        XCTAssertEqual(center.pendingCount, 1)
        ledger.rules.setPolicy(.allow, for: "/Applications/Google Chrome.app")
        ledger.revalidateAlerts()
        XCTAssertEqual(center.pendingCount, 0, "a pending alert disappears the moment the app gets a process-wide rule")
        let other = ConnectionAlert(appID: "/Applications/Google Chrome.app", appName: "Google Chrome", host: "2607:6bc0::11", address: "2607:6bc0::11", port: 443, proto: "TCP")
        center.report(other)
        XCTAssertEqual(center.pendingCount, 0, "and new addresses of that app stay silent")
    }

    func testDenyPolicyAlsoSilencesAlerts() {
        let ledger = Ledger(directory: tempDir())
        ledger.rules.silentMode = .off
        ledger.rules.setPolicy(.deny, for: "/Applications/Foo.app")
        let a = ConnectionAlert(appID: "/Applications/Foo.app", appName: "Foo", host: "x.example.com", address: "203.0.113.7", port: 443, proto: "TCP")
        ledger.alerts.report(a)
        XCTAssertEqual(ledger.alerts.pendingCount, 0)
    }

    func testSwitchingToSilentModeClearsPendingAlerts() {
        let ledger = Ledger(directory: tempDir())
        ledger.rules.silentMode = .off
        ledger.alerts.report(ConnectionAlert(appID: "/Applications/Foo.app", appName: "Foo", host: "x.example.com", address: "203.0.113.7", port: 443, proto: "TCP"))
        XCTAssertEqual(ledger.alerts.pendingCount, 1)
        ledger.rules.silentMode = .allow
        ledger.revalidateAlerts()
        XCTAssertEqual(ledger.alerts.pendingCount, 0)
    }

    func testAlertScopeDefaultsToWholeApp() {
        XCTAssertEqual(RulesModel.Scope.any.rawValue, "This App (Any Server)")
        XCTAssertEqual(RulesModel.Scope.allCases.first, .any)
        let m = RulesModel(directory: tempDir())
        m.silentMode = .off
        let a = ConnectionAlert(appID: "/Applications/Foo.app", appName: "Foo", host: "2607:6bc0::10", address: "2607:6bc0::10", port: 443, proto: "TCP")
        m.addRule(from: a, verdict: .allow, scope: .any, lifetime: .forever)
        let other = Connection(process: ProcessIdentity(path: "/Applications/Foo.app/Contents/MacOS/Foo"), host: nil, address: "2607:6bc0::99", port: 8443)
        XCTAssertEqual(m.engine.evaluate(other), .allow, "one click covers every other address of the app")
    }

    // MARK: chart

    private func ledgerWithTraffic(minutes: Double) -> Ledger {
        let l = Ledger(directory: tempDir())
        l.installDemoData()
        var pts: [TrafficPoint] = []
        let n = Int(minutes * 60 / 1.5)
        for i in 0..<n { pts.append(TrafficPoint(date: Date().addingTimeInterval(-Double(n - i) * 1.5), rx: Double(i % 9) * 1000, tx: Double(i % 4) * 500)) }
        l.history = pts
        return l
    }

    func testFiveMinuteChartIsFilledEdgeToEdge() {
        let l = ledgerWithTraffic(minutes: 5)
        let layout = l.chartLayout(.fiveMinutes)
        XCTAssertGreaterThanOrEqual(layout.bars.count, 50)
        XCTAssertEqual(layout.bars.first?.start, layout.start)
        XCTAssertEqual(layout.bars.last?.end, layout.end)
        for (a, b) in zip(layout.bars, layout.bars.dropFirst()) { XCTAssertEqual(a.end, b.start, "bars tile without gaps") }
        XCTAssertGreaterThan(layout.bars.filter { $0.rx + $0.tx > 0 }.count, layout.bars.count * 8 / 10, "real traffic fills most bars")
    }

    func testFreshSessionDoesNotCollapseToOneBar() {
        let l = ledgerWithTraffic(minutes: 1)
        for r in TimeRange.allCases {
            let layout = l.chartLayout(r)
            XCTAssertGreaterThanOrEqual(layout.bars.count, 1, r.rawValue)
        }
        let five = l.chartLayout(.fiveMinutes)
        XCTAssertLessThanOrEqual(five.end.timeIntervalSince(five.start), 75, "the window fits the minute of data that exists")
        XCTAssertGreaterThanOrEqual(five.bars.count, 30)
    }

    func testLongRangesBucketMinuteData() {
        let l = Ledger(directory: tempDir())
        l.installDemoData()
        let hour = l.chartLayout(.hour)
        XCTAssertGreaterThanOrEqual(hour.bars.count, 1)
        XCTAssertEqual(hour.bars.last?.end, hour.end)
        let week = l.chartLayout(.week)
        XCTAssertEqual(week.bars.first?.start, week.start)
        XCTAssertTrue(week.peak >= 1)
    }

    func testDefaultRangeIsFiveMinutes() {
        XCTAssertEqual(TimeRange.allCases.first, .fiveMinutes)
    }

    // MARK: names

    func testVersionedBinariesResolveToTheirTool() {
        let a = AppIdentity.resolve(processPath: "/Users/x/.local/share/claude/versions/2.1.308")
        XCTAssertEqual(a.name, "claude")
        XCTAssertEqual(a.id, "/Users/x/.local/share/claude")
        XCTAssertEqual(AppIdentity.resolve(processPath: "/opt/homebrew/Cellar/gh/2.103.0/bin/gh").name, "gh")
        XCTAssertEqual(AppIdentity.resolve(processPath: "/opt/tool/3.4.5").name, "tool")
    }

    func testExtensionsAreSeparateRowsSharingTheirAppsRules() {
        let ext = AppIdentity.resolve(processPath: "/Applications/Telegram.app/Contents/PlugIns/Share.appex/Contents/MacOS/Share")
        XCTAssertTrue(ext.isExtension)
        XCTAssertEqual(ext.name, "Telegram")
        XCTAssertEqual(ext.ruleKey, "/Applications/Telegram.app")
        XCTAssertNotEqual(ext.id, AppIdentity.resolve(processPath: "/Applications/Telegram.app/Contents/MacOS/Telegram").id)
    }

    func testLegacyDemoOrGoneProcessesAreNotPersistedAsApps() {
        let dir = tempDir()
        let store = StateStore.standard(base: dir)
        store.save(PersistedState(apps: [
            PersistedApp(id: "pid 123", name: "pid 123", bundlePath: nil, isSystem: false, totalIn: 1, totalOut: 1, lastActive: Date()),
            PersistedApp(id: "/Users/x/.local/share/claude/versions/2.1.308", name: "2.1.308", bundlePath: nil, isSystem: false, totalIn: 10, totalOut: 5, lastActive: Date()),
            PersistedApp(id: "/Users/x/.local/share/claude/versions/2.1.309", name: "2.1.309", bundlePath: nil, isSystem: false, totalIn: 1, totalOut: 1, lastActive: Date()),
        ], buckets: []))
        let ledger = Ledger(directory: dir)
        XCTAssertEqual(ledger.apps.map(\.identity.name), ["claude"], "version numbers merge into the tool, ghost pids vanish")
        XCTAssertEqual(ledger.apps.first?.totalIn, 11)
    }

    // MARK: settings

    func testLocalRangesParsing() {
        let r = LocalRanges()
        XCTAssertEqual(r.set("100.64.0.0/10, 10.5.0.0/16\n203.0.113.9"), [])
        XCTAssertTrue(r.contains("100.100.1.1"))
        XCTAssertTrue(r.contains("203.0.113.9"))
        XCTAssertFalse(r.contains("100.128.0.1"))
        XCTAssertEqual(r.set("nonsense, 1.2.3.4/99"), ["nonsense", "1.2.3.4/99"])
        XCTAssertFalse(r.contains("100.100.1.1"))
    }

    func testRateUnitFormatting() {
        let s = AppSettings.shared
        let old = s.trafficRateUnit
        defer { s.trafficRateUnit = old }
        s.trafficRateUnit = .bytes
        XCTAssertEqual(s.formatRate(0), "0 bytes/s")
        s.trafficRateUnit = .bits
        XCTAssertEqual(s.formatRate(125_000), "1.0 Mbit/s")
        XCTAssertEqual(s.formatRate(10), "80 bit/s")
    }

    func testUnknownNetworkActions() {
        let m = RulesModel(directory: tempDir())
        m.ruleSet.automaticProfileSwitching = true
        let work = m.ruleSet.profiles[1].id
        m.ruleSet.unknownNetworkAction = .activate(work)
        m.applyNetwork(NetworkWatcher.Network(signature: "x", name: "x"))
        XCTAssertEqual(m.activeProfile?.id, work)
        m.activate(m.ruleSet.profiles[0].id)
        m.ruleSet.unknownNetworkAction = .doNothing
        m.applyNetwork(NetworkWatcher.Network(signature: "y", name: "y"))
        XCTAssertEqual(m.activeProfile?.id, m.ruleSet.profiles[0].id)
    }

    // MARK: updates

    func testPreReleaseVersionOrdering() {
        XCTAssertTrue(UpdateChecker.isNewer("v1.0.1", than: "1.0.0"))
        XCTAssertFalse(UpdateChecker.isNewer("v1.0.0", than: "1.0.1"))
    }

    // MARK: settings window structure (mirrors Little Snitch's tabs, minus features Rat does not have)

    func testSettingsTabsFollowTheReferenceOrder() throws {
        let src = try String(contentsOf: URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().appendingPathComponent("App/Views/SettingsWindow.swift"), encoding: .utf8)
        let labels = ["General", "Control Center", "Alert", "Monitor", "APS", "Security", "Notifications", "Update", "Advanced"]
        var last = src.startIndex
        for l in labels {
            guard let r = src.range(of: "Label(\"\(l)\"", range: last..<src.endIndex) else { return XCTFail("tab \(l) missing or out of order") }
            last = r.upperBound
        }
    }

    // MARK: data written by 1.0.0

    func testRepairMovesIPsOutOfDomainAndNormalisesVersionedPaths() {
        var set = RuleSet.standard()
        set.rules = [
            Rule(verdict: .allow, processPath: "/Applications/Warp.app", remoteDomain: "2600:1901:0:5e8a::"),
            Rule(verdict: .allow, processPath: "/Applications/Warp.app", remoteDomain: "20.250.119.72"),
            Rule(verdict: .allow, processPath: "/Applications/Warp.app", remoteDomain: "github.com"),
            Rule(verdict: .allow, processPath: "/Users/x/.local/share/claude/versions/2.1.308"),
        ]
        RulesModel.repair(&set)
        XCTAssertNil(set.rules[0].remoteDomain)
        XCTAssertEqual(set.rules[0].remoteAddress, "2600:1901:0:5e8a::")
        XCTAssertEqual(set.rules[1].remoteAddress, "20.250.119.72")
        XCTAssertEqual(set.rules[2].remoteDomain, "github.com", "real domains are untouched")
        XCTAssertEqual(set.rules[3].processPath, "/Users/x/.local/share/claude")
        let c = Connection(process: ProcessIdentity(path: "/Applications/Warp.app/Contents/MacOS/warp"), host: nil, address: "20.250.119.72", port: 443)
        XCTAssertEqual(RuleEngine(ruleSet: set).evaluate(c), .allow, "the repaired rule now actually matches")
    }

    func testDomainScopeOnAnIPAddressBecomesAnAddressRule() {
        let m = RulesModel(directory: tempDir())
        m.silentMode = .off
        let a = ConnectionAlert(appID: "/Applications/Foo.app", appName: "Foo", host: "2607:6bc0::10", address: "2607:6bc0::10", port: 443, proto: "TCP")
        m.addRule(from: a, verdict: .allow, scope: .domain, lifetime: .forever)
        XCTAssertNil(m.ruleSet.rules[0].remoteDomain)
        XCTAssertEqual(m.ruleSet.rules[0].remoteAddress, "2607:6bc0::10")
    }
}

/// 1.0.2: helper processes group with their app, and apps that are denied outright are handed to the root daemon.
final class Release102Tests: XCTestCase {
    func testSteamAndChromeHelpersGroupUnderTheirApp() {
        let steamBase = "/Users/me/Library/Application Support/Steam/Steam.AppBundle"
        for exe in ["Steam/Contents/MacOS/steam_osx", "Steam/Contents/MacOS/ipcserver", "Steam/Contents/Frameworks/Steam Helper.app/Contents/MacOS/Steam Helper"] {
            let id = AppIdentity.resolve(processPath: "\(steamBase)/\(exe)")
            XCTAssertEqual(id.id, steamBase, exe)
            XCTAssertEqual(id.name, "Steam")
        }
        let chrome = AppIdentity.resolve(processPath: "/Applications/Google Chrome.app/Contents/Frameworks/Google Chrome Framework.framework/Versions/1/Helpers/Google Chrome Helper (Renderer).app/Contents/MacOS/Google Chrome Helper (Renderer)")
        XCTAssertEqual(chrome.id, "/Applications/Google Chrome.app")
        let firefox = AppIdentity.resolve(processPath: "/Applications/Firefox.app/Contents/MacOS/plugin-container.app/Contents/MacOS/plugin-container")
        XCTAssertEqual(firefox.id, "/Applications/Firefox.app")
    }

    @MainActor func testDeniedAppsAreWholeAppDenyWithoutAllowExceptions() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("rat-102-\(UUID())")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let ledger = Ledger(directory: dir)
        ledger.rules.ruleSet.rules = [
            Rule(verdict: .deny, processPath: "/Applications/Google Chrome.app"),
            Rule(verdict: .deny, processPath: "/Applications/Firefox.app"),
            Rule(verdict: .allow, processPath: "/Applications/Firefox.app", remoteDomain: "mozilla.org"),
            Rule(verdict: .deny, processPath: "/Applications/Steam.app", remoteDomain: "ads.example"),
        ]
        ledger.rules.ruleSet.silentVerdict = .allow
        XCTAssertEqual(ledger.deniedAppPaths, ["/Applications/Google Chrome.app"])
    }
}

final class Release103Tests: XCTestCase {
    func testLonePinNeverZoomsBelowRegionalView() {
        let r = MapPane.region(fitting: [CLLocationCoordinate2D(latitude: 35.7, longitude: 51.4)])
        XCTAssertGreaterThanOrEqual(r.span.latitudeDelta, 15)
        XCTAssertGreaterThanOrEqual(r.span.longitudeDelta, 15)
        let two = MapPane.region(fitting: [CLLocationCoordinate2D(latitude: 35.7, longitude: 51.4), CLLocationCoordinate2D(latitude: 52.5, longitude: 13.4)])
        XCTAssertGreaterThan(two.span.longitudeDelta, 15)
        XCTAssertGreaterThanOrEqual(MapPane.region(fitting: []).span.latitudeDelta, 15)
    }
}
