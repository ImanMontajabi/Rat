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

    /// Waits until a switch is on or off (a switch reports its own value, 1 or 0).
    private func waitSwitch(_ e: XCUIElement, on: Bool, timeout: TimeInterval = 5) -> Bool {
        let n = on ? 1 : 0
        return XCTWaiter().wait(for: [expectation(for: NSPredicate(format: "value == %@ OR value == %@", NSNumber(value: n), "\(n)"), evaluatedWith: e)], timeout: timeout) == .completed
    }

    /// Waits until a text shows `text` (as its label or its value, whichever the element reports).
    private func waitText(_ e: XCUIElement, _ text: String, timeout: TimeInterval = 5) -> Bool {
        XCTWaiter().wait(for: [expectation(for: NSPredicate(format: "label == %@ OR value == %@", text, text), evaluatedWith: e)], timeout: timeout) == .completed
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

    // MARK: three levels: app, process, connection

    /// A process row and a connection row have their own ✗/✓; without a choice of their own they show the wider
    /// row's (Chrome is allowed as a whole in the demo data) as "inherited".
    func testProcessAndConnectionRowsHaveTheirOwnToggles() {
        expand("Google Chrome")
        expand("Google Chrome Helper")
        let helper = el("process-row-Google Chrome Helper")
        XCTAssertTrue(helper.waitForExistence(timeout: 5))
        let helperDeny = helper.buttons["policy-deny"], helperAllow = helper.buttons["policy-allow"]
        XCTAssertEqual(helperAllow.value as? String, "inherited", "follows the app's ✓")
        XCTAssertEqual(helperDeny.value as? String, "off")
        let video = el("remote-policy-video.example.net")
        XCTAssertTrue(video.waitForExistence(timeout: 5))
        XCTAssertEqual(video.buttons["policy-allow"].value as? String, "inherited")

        helperDeny.click()
        XCTAssertTrue(waitValue(helperDeny, "on"), "the helper is denied on its own")
        XCTAssertTrue(waitValue(video.buttons["policy-deny"], "inherited"), "its connection follows the helper now")
        XCTAssertEqual(el("app-row-Google Chrome").buttons["policy-allow"].value as? String, "on", "the app keeps its ✓")
        XCTAssertEqual(el("remote-policy-demo0.example.com").buttons["policy-allow"].value as? String, "inherited", "the main process's connections still follow the app")

        video.buttons["policy-allow"].click()
        XCTAssertTrue(waitValue(video.buttons["policy-allow"], "on"), "an exception for one connection")
        XCTAssertEqual(el("remote-policy-cdn.example.net").buttons["policy-deny"].value as? String, "inherited", "the helper's other connection stays denied")
        XCTAssertEqual(helperDeny.value as? String, "on")

        helperDeny.click()
        XCTAssertTrue(waitValue(helperDeny, "off"), "clicking the active choice clears it")
        XCTAssertTrue(waitValue(helperAllow, "inherited"))
    }

    /// Services that work for every app have no one-click Deny of their own either.
    func testSharedServicesAreLocked() {
        expand("macOS")
        let dns = el("process-row-mDNSResponder")
        XCTAssertTrue(dns.waitForExistence(timeout: 5))
        XCTAssertTrue(dns.descendants(matching: .any)["policy-locked"].exists, "mDNSResponder")
        XCTAssertFalse(dns.buttons["policy-deny"].exists)
        XCTAssertTrue(el("process-row-apsd").descendants(matching: .any)["policy-locked"].exists, "apsd")
    }

    /// The inspector lists the rules about the selected row and sets that row's ✗/✓.
    func testInspectorShowsTheSelectedRowsRules() {
        expand("Steam")
        el("process-row-Steam Helper").click()
        XCTAssertTrue(inspectorTitle().contains("Steam Helper"), inspectorTitle())
        let rules = el("inspector-rules")
        XCTAssertTrue(rules.waitForExistence(timeout: 5))
        XCTAssertEqual(rules.value as? String, "1", "Steam's UDP rule covers its helper")
        expand("Steam Helper")
        el("remote-row-demo5.example.com").click()
        XCTAssertTrue(inspectorTitle().contains("demo5.example.com"), inspectorTitle())
        XCTAssertTrue(waitValue(el("inspector-rules"), "1"), "the UDP 27015 rule matches this connection")
        let deny = el("inspector-policy").buttons["policy-deny"]
        XCTAssertTrue(deny.waitForExistence(timeout: 5))
        deny.click()
        XCTAssertTrue(waitValue(deny, "on"))
        XCTAssertTrue(waitValue(el("inspector-rules"), "2"), "the connection's own ✗ is listed")
        XCTAssertEqual(el("remote-policy-demo5.example.com").buttons["policy-deny"].value as? String, "on", "the list shows the same choice")
        el("app-row-Telegram").click()
        XCTAssertTrue(waitValue(el("inspector-rules"), "1"), "Telegram's rule from an alert")
    }

    /// Manage Rules… opens the Rules window on the selected process, and New Rule starts from it.
    func testManageRulesOpensOnTheSelection() {
        expand("Steam")
        el("process-row-Steam Helper").click()
        let manage = el("manage-rules")
        XCTAssertTrue(manage.waitForExistence(timeout: 5))
        manage.click()
        let window = app.windows["Rules"]
        XCTAssertTrue(window.waitForExistence(timeout: 5))
        let title = el("rules-title")
        XCTAssertTrue(title.waitForExistence(timeout: 5))
        XCTAssertTrue(waitText(title, "Steam Helper"), "\(title.label) \(title.value ?? "nil")")
        XCTAssertTrue(waitText(el("rules-count"), "1 rule"))
        XCTAssertTrue(el("rules-app-Steam").exists, "the Apps / Processes section lists the app")
        XCTAssertTrue(el("rules-process-Steam Helper").exists, "and the process the window opened on")

        window.toolbars.buttons["New Rule"].click()
        let exe = el("rule-executable")
        XCTAssertTrue(exe.waitForExistence(timeout: 5))
        XCTAssertEqual(exe.value as? String, "/Applications/Demo/Steam.app/Contents/MacOS/Steam Helper")
        XCTAssertEqual(el("rule-process").value as? String, "/Applications/Demo/Steam.app")
        window.sheets.buttons["Cancel"].click()
        XCTAssertTrue(waitGone(exe))

        el("rules-app-Steam").click()
        XCTAssertTrue(waitText(el("rules-title"), "Steam"))
    }

    func testCommandLineToolShowsWhoStartedIt() {
        el("app-row-git-remote-https").click()
        XCTAssertTrue(app.staticTexts["Warp (pid 700)"].waitForExistence(timeout: 5), "Started by: Warp")
    }

    // MARK: direction

    /// A peer's connection to Steam's Remote Play port is tagged `↓ Incoming` and has no ✗/✓; Telegram's long
    /// download is tagged `↓ stream` and keeps them. App rows show neither.
    func testIncomingAndStreamRowsAreTagged() {
        XCTAssertFalse(el("app-row-Steam").descendants(matching: .any)["badge-Incoming"].exists, "the app row keeps its room for routes")
        expand("Steam")
        let incoming = el("remote-row-demo4.example.com")
        XCTAssertTrue(incoming.waitForExistence(timeout: 5))
        XCTAssertTrue(incoming.label.contains("Incoming"), incoming.label)
        XCTAssertTrue(incoming.label.contains("27036"), "the port of this Mac the peer connected to: \(incoming.label)")
        XCTAssertFalse(el("remote-policy-demo4.example.com").buttons["policy-deny"].exists, "no ✗/✓ for a connection a peer started")
        incoming.click()
        XCTAssertTrue(inspectorTitle().contains("demo4.example.com"), inspectorTitle())
        XCTAssertFalse(el("inspector-policy").exists, "the inspector offers none either")

        expand("Telegram")
        let stream = el("remote-row-demo2.example.com")
        XCTAssertTrue(stream.waitForExistence(timeout: 5))
        XCTAssertTrue(stream.label.contains("stream"), stream.label)
        XCTAssertFalse(stream.label.contains("Incoming"))
        XCTAssertTrue(el("remote-policy-demo2.example.com").buttons["policy-deny"].exists, "a stream this Mac opened can be denied")
    }

    // MARK: flags and Hide Local

    /// Places carry their country's flag: the Summary's Top Countries and a connection's location in the inspector.
    func testPlacesShowTheirFlags() {
        XCTAssertTrue(app.staticTexts["🇪🇸 Spain"].waitForExistence(timeout: 5), "Top Countries")
        expand("Google Chrome")
        let london = el("remote-row-demo0.example.com")
        XCTAssertTrue(london.waitForExistence(timeout: 5))
        london.click()
        XCTAssertTrue(app.staticTexts["🇬🇧 London, United Kingdom"].waitForExistence(timeout: 5), "the inspector's location")
    }

    /// The Local switch beside the search field, turned off, leaves out Bonjour and LAN connections, and the
    /// processes that have only those; a connection through a local proxy stays (it leaves the Mac). It remembers
    /// its state for the next launch.
    func testLocalSwitchHidesLocalConnections() {
        let chip = el("show-local")
        XCTAssertTrue(chip.waitForExistence(timeout: 5))
        XCTAssertTrue(waitSwitch(chip, on: true), "local connections are shown at first: \(String(describing: chip.value))")
        XCTAssertTrue(app.staticTexts["Local"].exists, "a labeled switch")
        let counts = el("summary-counts")
        XCTAssertTrue(counts.waitForExistence(timeout: 5))
        let before = [counts.label, counts.value as? String ?? ""].joined()
        expand("macOS")
        XCTAssertTrue(el("process-row-rapportd").waitForExistence(timeout: 5), "a service that talks only to the LAN")
        expand("mDNSResponder")
        XCTAssertTrue(el("remote-row-224.0.0.251").waitForExistence(timeout: 5), "Bonjour")
        expand("Firefox")
        XCTAssertTrue(el("remote-row-127.0.0.1").waitForExistence(timeout: 5))

        chip.click()
        XCTAssertTrue(waitSwitch(chip, on: false))
        XCTAssertTrue(waitGone(el("process-row-rapportd")), "a process with only local connections is hidden")
        XCTAssertTrue(waitGone(el("remote-row-224.0.0.251")))
        XCTAssertTrue(el("remote-row-dns.example").exists, "mDNSResponder's outside connection stays")
        XCTAssertTrue(el("remote-row-127.0.0.1").exists, "through Tor: it leaves the Mac")
        XCTAssertFalse(el("summary-filtered").exists, "a standing preference, not a filter")
        XCTAssertNotEqual([counts.label, counts.value as? String ?? ""].joined(), before, "the Summary counts fewer domains")

        chip.click()
        XCTAssertTrue(waitSwitch(chip, on: true))
        XCTAssertTrue(el("process-row-rapportd").waitForExistence(timeout: 5))
    }

    // MARK: VPN and proxy tags

    func testVPNAndProxyTagsRender() {
        // Collapsed, the app's row already shows where its connections go.
        XCTAssertTrue(el("app-row-Telegram").descendants(matching: .any)["badge-VPN · Windscribe"].waitForExistence(timeout: 5), "the app row")
        XCTAssertTrue(el("app-row-Firefox").descendants(matching: .any)["badge-Proxy · Tor"].exists, "the first tag; more fold into a count when the row is narrow")
        XCTAssertFalse(el("app-row-Steam").descendants(matching: .any)["badge-VPN · Windscribe"].exists, "no tag without such connections")
        expand("Telegram")
        XCTAssertTrue(el("process-row-Telegram Helper").waitForExistence(timeout: 5))
        XCTAssertTrue(el("process-row-Telegram Helper").descendants(matching: .any)["badge-VPN · Windscribe"].exists, "the process row")
        expand("Telegram Helper")
        let vpn = el("remote-row-demo3.example.com")
        XCTAssertTrue(vpn.waitForExistence(timeout: 5))
        XCTAssertTrue(vpn.label.contains("VPN · Windscribe"), vpn.label + " (a tag folded to its symbol still names itself)")
        XCTAssertTrue(vpn.label.contains("TCP 5222"), vpn.label + " (the port whole, and a number never written as 5.222)")
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

    /// The map's pulses move while the window is seen and its lines carry traffic: they stop while Rat is hidden
    /// and when the search leaves only idle connections.
    func testMapFlowsMoveOnlyWhileSeenAndBusy() {
        let flows = el("map-flows")
        XCTAssertTrue(flows.waitForExistence(timeout: 5))
        XCTAssertTrue(waitValue(flows, "3 moving"), "London down, Paris both ways, Madrid up: \(flows.value ?? "nil")")
        app.typeKey("h", modifierFlags: .command)
        XCTAssertTrue(waitValue(flows, "paused"), "hidden: no frames drawn: \(flows.value ?? "nil")")
        app.activate()
        XCTAssertTrue(waitValue(flows, "3 moving", timeout: 10), "\(flows.value ?? "nil")")
        search("git")
        XCTAssertTrue(waitValue(flows, "idle"), "git's server is quiet: \(flows.value ?? "nil")")
        search("")
        XCTAssertTrue(waitValue(flows, "3 moving"))
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
