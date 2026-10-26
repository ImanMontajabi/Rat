import XCTest

/// Clicks through Rat's main flows on its fixed demo data (`RAT_DEMO_MAP=1`): a temporary data folder, its own
/// preferences, no helper, no update check. The UITest build has its own bundle identifier, so the Rat you are
/// running is neither quit nor touched. Needs a logged-in GUI session: run `scripts/test-ui.sh` (not part of CI).
final class RatUITests: XCTestCase {
    private var app: XCUIApplication!

    override func setUpWithError() throws {
        continueAfterFailure = false
        app = XCUIApplication()
        app.launchEnvironment["RAT_DEMO_MAP"] = "1"
        // Start from a fresh window: a window minimized in an earlier run would come back minimized, and every
        // click and keystroke would miss it.
        app.launchArguments += ["-ApplePersistenceIgnoreState", "YES"]
        app.launch()
        XCTAssertTrue(el("app-row-Google Chrome").waitForExistence(timeout: 20), "the monitor window shows the demo apps")
    }

    override func tearDownWithError() throws {
        app?.terminate()
    }

    // MARK: helpers

    private func el(_ id: String) -> XCUIElement { app.descendants(matching: .any).matching(identifier: id).firstMatch }

    private func expand(_ name: String) {
        let d = el("disclose-\(name)")
        XCTAssertTrue(d.waitForExistence(timeout: 5), "disclosure for \(name)")
        d.click()
    }

    private func waitGone(_ e: XCUIElement, timeout: TimeInterval = 5) -> Bool {
        let p = NSPredicate(format: "exists == false")
        return XCTWaiter().wait(for: [expectation(for: p, evaluatedWith: e)], timeout: timeout) == .completed
    }

    private func inspectorTitle() -> String {
        let t = el("inspector-title")
        _ = t.waitForExistence(timeout: 5)
        return [t.label, t.value as? String ?? ""].filter { !$0.isEmpty }.joined(separator: " ")
    }

    /// Waits until the element's accessibility value is `value` (SwiftUI updates after the click is handled).
    private func waitValue(_ e: XCUIElement, _ value: String, timeout: TimeInterval = 5) -> Bool {
        XCTWaiter().wait(for: [expectation(for: NSPredicate(format: "value == %@", value), evaluatedWith: e)], timeout: timeout) == .completed
    }

    private func isActive(_ profile: String) -> Bool { el("profile-\(profile)").descendants(matching: .any)["profile-active"].exists }

    /// Types into the search field. Right after a menu closes the click may not focus the field, so it retries
    /// until the field holds the text.
    private func search(_ text: String) {
        let f = el("search-field")
        for _ in 0..<3 {
            f.click()
            f.typeKey("a", modifierFlags: .command)
            f.typeKey(.delete, modifierFlags: [])
            if !text.isEmpty { f.typeText(text) }
            if (f.value as? String ?? "") == text { return }
        }
        XCTFail("could not type \(text) into the search field: \(f.value ?? "nil")")
    }

    // MARK: process tree

    func testAppExpandsIntoDirectConnectionsAndSubProcesses() {
        XCTAssertFalse(el("remote-row-demo0.example.com").exists, "collapsed at launch")
        expand("Google Chrome")
        XCTAssertTrue(el("remote-row-demo0.example.com").waitForExistence(timeout: 5), "the main process's own connection")
        XCTAssertTrue(el("remote-row-demo1.example.com").exists)
        XCTAssertTrue(el("process-row-Google Chrome Helper").exists, "the helper is a node under the app")
        XCTAssertFalse(el("remote-row-cdn.example.net").exists, "the helper's connections stay folded")
        expand("Google Chrome Helper")
        XCTAssertTrue(el("remote-row-cdn.example.net").waitForExistence(timeout: 5), "Sub-app → its own connection")
        XCTAssertTrue(el("remote-row-video.example.net").exists)
        expand("Google Chrome")
        XCTAssertTrue(waitGone(el("remote-row-demo0.example.com")), "collapsing hides the tree")
    }

    func testMacOSRowListsServicesAsNodes() {
        expand("macOS")
        XCTAssertTrue(el("process-row-mDNSResponder").waitForExistence(timeout: 5))
        XCTAssertTrue(el("process-row-apsd").exists)
        XCTAssertFalse(el("app-row-macOS").buttons["policy-deny"].exists, "no one-click Deny for all of macOS")
    }

    func testSelectionScopesTheInspector() {
        expand("Google Chrome")
        expand("Google Chrome Helper")
        el("process-row-Google Chrome Helper").click()
        XCTAssertTrue(inspectorTitle().contains("Google Chrome Helper"), inspectorTitle())
        XCTAssertTrue(inspectorTitle().contains("Process of Google Chrome"), inspectorTitle())
        el("remote-row-video.example.net").click()
        XCTAssertTrue(inspectorTitle().contains("video.example.net"), inspectorTitle())
        el("app-row-Google Chrome").click()
        XCTAssertTrue(inspectorTitle().hasPrefix("Google Chrome") && !inspectorTitle().contains("Process of"), inspectorTitle())
        el("app-row-Google Chrome").click()
        XCTAssertTrue(waitGone(el("inspector-title")), "clicking the selected app again shows the Summary")
        XCTAssertTrue(app.staticTexts["Summary"].exists)
    }

    func testCommandLineToolShowsWhoStartedIt() {
        el("app-row-git-remote-https").click()
        XCTAssertTrue(app.staticTexts["Warp (pid 700)"].waitForExistence(timeout: 5), "Started by: Warp")
    }

    // MARK: VPN and proxy tags

    func testVPNAndProxyTagsRender() {
        expand("Telegram")
        let vpn = el("remote-row-demo3.example.com")
        XCTAssertTrue(vpn.waitForExistence(timeout: 5))
        XCTAssertTrue(vpn.label.contains("VPN · Windscribe"), vpn.label)
        XCTAssertFalse(el("remote-row-demo2.example.com").label.contains("VPN"), "only the tunnelled connection is tagged")
        expand("Firefox")
        XCTAssertTrue(el("remote-row-news.example.org").waitForExistence(timeout: 5))
        XCTAssertTrue(el("remote-row-news.example.org").label.contains("Proxy · ssh"), el("remote-row-news.example.org").label)
        XCTAssertTrue(el("remote-row-127.0.0.1").label.contains("Proxy · Tor"), el("remote-row-127.0.0.1").label)
        // The inspector shows the full tag, with the tunnel's interface.
        vpn.click()
        XCTAssertTrue(el("badge-VPN · Windscribe · utun3").waitForExistence(timeout: 5))
    }

    func testSearchWordsFilterByRoute() {
        search("vpn")
        XCTAssertTrue(waitGone(el("app-row-Google Chrome")), "apps without VPN connections are hidden")
        XCTAssertTrue(el("app-row-Telegram").exists)
        XCTAssertFalse(el("app-row-Firefox").exists)
        search("proxy")
        XCTAssertTrue(el("app-row-Firefox").waitForExistence(timeout: 5))
        XCTAssertFalse(el("app-row-Telegram").exists)
        search("")
        XCTAssertTrue(el("app-row-Google Chrome").waitForExistence(timeout: 5))
    }

    func testRouteFilterChip() {
        el("route-filter").click()
        app.menuItems["Through a VPN"].click()
        XCTAssertTrue(waitGone(el("app-row-Steam")))
        XCTAssertTrue(el("app-row-Telegram").exists)
        el("route-filter").click()
        app.menuItems["All Connections"].click()
        XCTAssertTrue(el("app-row-Steam").waitForExistence(timeout: 5))
    }

    /// The map draws only what the list shows: the route chip and the search narrow its places too.
    func testMapFollowsTheRouteChipAndSearch() {
        let map = el("map-places")
        XCTAssertTrue(map.waitForExistence(timeout: 5))
        XCTAssertTrue((map.value as? String ?? "").contains("London"), "\(map.value ?? "nil")")
        el("route-filter").click()
        app.menuItems["Through a VPN"].click()
        XCTAssertTrue(waitValue(map, "Paris"), "only the tunnelled connection: \(map.value ?? "nil")")
        el("route-filter").click()
        app.menuItems["Through a Proxy"].click()
        XCTAssertTrue(waitValue(map, "Madrid, Proxy · Stockholm"), "the unmasked destination and its proxy: \(map.value ?? "nil")")
        el("route-filter").click()
        app.menuItems["All Connections"].click()
        search("vpn")
        XCTAssertTrue(waitValue(map, "Paris"), "the search word works like the chip: \(map.value ?? "nil")")
        search("London")
        XCTAssertTrue(waitValue(map, "London"), "a city: only the lines to it: \(map.value ?? "nil")")
        search("")
        XCTAssertTrue((map.value as? String ?? "").contains("Madrid"))
    }

    /// The Summary counts what the list shows, and says so while a filter is on.
    func testSummaryFollowsTheFilter() {
        let counts = el("summary-counts")
        XCTAssertTrue(counts.waitForExistence(timeout: 5))
        XCTAssertFalse(el("summary-filtered").exists, "no filter, no indicator")
        func text() -> String { [counts.label, counts.value as? String ?? ""].filter { !$0.isEmpty }.joined(separator: " ") }
        let all = text()
        el("route-filter").click()
        app.menuItems["Through a Proxy"].click()
        XCTAssertTrue(el("summary-filtered").waitForExistence(timeout: 5))
        let firefox = NSPredicate(format: "label == %@ OR value == %@", "1 process, 2 domains", "1 process, 2 domains")
        XCTAssertTrue(XCTWaiter().wait(for: [expectation(for: firefox, evaluatedWith: counts)], timeout: 5) == .completed, "Firefox alone: \(text())")
        XCTAssertTrue(app.staticTexts["Firefox"].exists, "Top Processes is the listed app")
        el("route-filter").click()
        app.menuItems["All Connections"].click()
        XCTAssertTrue(waitGone(el("summary-filtered")))
        search("London")
        XCTAssertTrue(el("summary-filtered").waitForExistence(timeout: 5), "the search filters it too: \(text())")
        search("")
        XCTAssertTrue(waitGone(el("summary-filtered")))
        XCTAssertEqual(text(), all)
    }

    func testSearchByName() {
        search("telegram")
        XCTAssertTrue(waitGone(el("app-row-Steam")))
        XCTAssertTrue(el("app-row-Telegram").exists)
        search("Chrome Helper")
        XCTAssertTrue(el("app-row-Google Chrome").waitForExistence(timeout: 5), "processes are searched too")
    }

    // MARK: allow / deny

    func testDenyAndAllowToggles() {
        let deny = el("app-row-Steam").buttons["policy-deny"]
        let allow = el("app-row-Steam").buttons["policy-allow"]
        XCTAssertEqual(deny.value as? String, "off")
        deny.click()
        XCTAssertTrue(waitValue(deny, "on"), "Deny is on: \(deny.value ?? "nil")")
        el("only-denied").click()
        XCTAssertTrue(waitGone(el("app-row-Telegram")), "only denied apps are listed")
        XCTAssertTrue(el("app-row-Steam").exists)
        el("only-denied").click()
        allow.click()
        XCTAssertTrue(waitValue(allow, "on"))
        XCTAssertEqual(deny.value as? String, "off")
        allow.click()
        XCTAssertTrue(waitValue(allow, "off"), "clicking the active choice clears it")
    }

    // MARK: time range

    func testTimeRangeMenu() {
        el("time-range").click()
        app.menuItems["1 hour"].click()
        XCTAssertTrue(app.staticTexts["Last 1 hour"].waitForExistence(timeout: 5))
        el("time-range").click()
        app.menuItems["5 minutes"].click()
        XCTAssertTrue(app.staticTexts["Last 5 minutes"].waitForExistence(timeout: 5))
    }

    // MARK: rules window

    func testRulesWindowEditorAndProfiles() {
        app.typeKey("r", modifierFlags: [.command, .shift])
        let rules = app.windows["Rules"]
        XCTAssertTrue(rules.waitForExistence(timeout: 5))
        // The rule editor opens as a sheet and cancels without saving.
        rules.toolbars.buttons["New Rule"].click()
        let cancel = rules.sheets.buttons["Cancel"]
        XCTAssertTrue(cancel.waitForExistence(timeout: 5))
        XCTAssertTrue(rules.sheets.buttons["Save"].exists)
        cancel.click()
        XCTAssertTrue(waitGone(cancel))
        // Switch profile: Home is active; activate Work.
        XCTAssertTrue(isActive("Home"))
        XCTAssertFalse(isActive("Work"))
        el("profile-Work").click()
        let activate = el("activate-profile")
        XCTAssertTrue(activate.waitForExistence(timeout: 5))
        activate.click()
        XCTAssertTrue(el("profile-is-active").waitForExistence(timeout: 5))
        XCTAssertTrue(isActive("Work"), el("profile-Work").debugDescription)
        XCTAssertFalse(isActive("Home"))
    }

    // MARK: settings

    func testSettingsOpensEveryTab() {
        app.typeKey(",", modifierFlags: .command)
        let tabs = ["General", "Control Center", "Alert", "Monitor", "APS", "Security", "GeoIP", "Notifications", "Update", "Advanced"]
        XCTAssertTrue(app.windows["General"].waitForExistence(timeout: 5), "Settings opens on General")
        for tab in tabs {
            let button = app.toolbars.buttons[tab]
            XCTAssertTrue(button.waitForExistence(timeout: 5), tab)
            button.click()
            XCTAssertTrue(app.windows[tab].waitForExistence(timeout: 5), "the window shows \(tab)")
        }
        // Demo mode sees no helper, so Security offers to install one (never clicked here).
        app.toolbars.buttons["Security"].click()
        XCTAssertTrue(app.windows["Security"].buttons.matching(NSPredicate(format: "label BEGINSWITH 'Install'")).firstMatch.waitForExistence(timeout: 5))
    }

    // MARK: isolation

    /// Clicking around in demo mode leaves the real data folder alone: the deny list the root daemon reads, the
    /// rules, and the real preferences.
    func testDemoModeLeavesRealDataAlone() throws {
        let data = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Library/Application Support/com.imanmontajabi.Rat")
        func snapshot() -> [String: Data] {
            var out: [String: Data] = [:]
            for f in ["denied-apps.txt", "rules.json"] { out[f] = try? Data(contentsOf: data.appendingPathComponent(f)) }
            return out
        }
        let before = snapshot()
        let prefsBefore = UserDefaults.standard.persistentDomain(forName: "com.imanmontajabi.Rat")?.keys.sorted()
        el("app-row-Steam").buttons["policy-deny"].click()
        el("app-row-Telegram").buttons["policy-deny"].click()
        app.typeKey(",", modifierFlags: .command)
        XCTAssertTrue(app.windows["General"].waitForExistence(timeout: 5))
        app.toolbars.buttons["Monitor"].click()
        app.windows["Monitor"].checkBoxes.firstMatch.click()
        app.terminate()
        XCTAssertEqual(snapshot(), before, "the real deny list and rules are untouched")
        XCTAssertEqual(UserDefaults.standard.persistentDomain(forName: "com.imanmontajabi.Rat")?.keys.sorted(), prefsBefore, "no new real preferences")
    }
}
