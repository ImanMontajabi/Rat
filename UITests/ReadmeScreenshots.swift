import XCTest

/// The README's screenshots, taken from the demo data (`RAT_DEMO_MAP=1`: fixed apps, rules and traffic, nothing of
/// this Mac's). Skipped unless `RAT_SCREENSHOTS` is set; `scripts/readme-screenshots.sh` runs it and saves the
/// attachments (the sandboxed test runner cannot write outside its container) to `docs/screenshots`.
final class ReadmeScreenshots: XCTestCase {
    private var app: XCUIApplication!

    override func setUpWithError() throws {
        guard ProcessInfo.processInfo.environment["RAT_SCREENSHOTS"] != nil else {
            throw XCTSkip("README screenshots: run scripts/readme-screenshots.sh")
        }
        continueAfterFailure = false
        app = XCUIApplication()
        app.launchEnvironment["RAT_DEMO_MAP"] = "1"
        app.launchArguments += ["-ApplePersistenceIgnoreState", "YES"]
        app.launch()
        XCTAssertTrue(el("app-row-Google Chrome").waitForExistence(timeout: 20))
    }

    override func tearDownWithError() throws {
        app?.terminate()
    }

    private func el(_ id: String) -> XCUIElement { app.descendants(matching: .any).matching(identifier: id).firstMatch }

    private func save(_ window: XCUIElement, _ name: String) {
        Thread.sleep(forTimeInterval: 1.5)   // map tiles and animations settle
        let shot = XCTAttachment(data: window.screenshot().pngRepresentation, uniformTypeIdentifier: "public.png")
        shot.name = name
        shot.lifetime = .keepAlways
        add(shot)
    }

    /// The monitor filtered to connections through a VPN or proxy: Telegram opened down to its helper's tunnelled
    /// connection, Firefox's connections through ssh and Tor, the map's proxy hop and the filtered Summary.
    func testMonitor() throws {
        el("route-filter").click()
        app.menuItems["Through a VPN or Proxy"].click()
        XCTAssertTrue(el("app-row-Telegram").waitForExistence(timeout: 5))
        for name in ["Telegram", "Telegram Helper", "Firefox"] {
            let d = el("disclose-\(name)")
            XCTAssertTrue(d.waitForExistence(timeout: 5), name)
            d.click()
        }
        XCTAssertTrue(el("remote-row-demo3.example.com").waitForExistence(timeout: 5))
        XCTAssertTrue(el("summary-filtered").waitForExistence(timeout: 5))
        save(app.windows["Network Monitor"], "monitor-hierarchy-tags.png")
    }

    func testRulesWindow() throws {
        app.typeKey("r", modifierFlags: [.command, .shift])
        let rules = app.windows["Rules"]
        XCTAssertTrue(rules.waitForExistence(timeout: 5))
        save(rules, "rules-window.png")
    }

    func testSettingsWindow() throws {
        app.typeKey(",", modifierFlags: .command)
        let general = app.windows["General"]
        XCTAssertTrue(general.waitForExistence(timeout: 5))
        save(general, "settings-window.png")
    }
}
