import XCTest
import AppKit
@testable import Rat

/// The View Options menu is AppKit's, built once: its checkmarks come from the settings when it opens, and its items
/// set them. (Under XCTest the settings live in a throw-away suite.)
@MainActor
final class ViewOptionsMenuTests: XCTestCase {
    func testTheMenuShowsAndSetsTheSixViewOptions() throws {
        let s = AppSettings.shared
        XCTAssertNotIdentical(Preferences.store, UserDefaults.standard, "tests never write the real preferences")
        let saved = (s.groupBy, s.sortKey, s.includeLocalNetwork, s.includeNetworkExtensions, s.includeOtherUsers, s.floatOnTop)
        addTeardownBlock { @MainActor in
            (s.groupBy, s.sortKey, s.includeLocalNetwork, s.includeNetworkExtensions, s.includeOtherUsers, s.floatOnTop) = saved
        }
        let c = ViewOptionsMenuController()
        let m = c.menu
        XCTAssertEqual(m.items.map(\.title), ["Group By", "Sort By", "", "Show Local Network", "Show Network Extensions",
                                             "Show Connections of Other Users", "", "Float on Top"])
        XCTAssertIdentical(c.menu, m, "built once: a pass never rebuilds it")
        let group = try XCTUnwrap(m.items.first { $0.title == "Group By" }?.submenu)
        let sort = try XCTUnwrap(m.items.first { $0.title == "Sort By" }?.submenu)
        XCTAssertEqual(group.items.map(\.title), AppSettings.GroupBy.allCases.map(\.rawValue))
        XCTAssertEqual(sort.items.map(\.title), AppSettings.SortKey.allCases.map(\.rawValue))

        // Checkmarks follow the settings when a menu opens.
        s.groupBy = .country; s.sortKey = .traffic; s.includeOtherUsers = true; s.floatOnTop = false
        c.menuNeedsUpdate(group)
        XCTAssertEqual(group.items.filter { $0.state == .on }.map(\.title), ["Country"])
        XCTAssertEqual(sort.items.filter { $0.state == .on }.map(\.title), ["Traffic"])
        XCTAssertEqual(m.items.first { $0.title == "Show Connections of Other Users" }?.state, .on)
        XCTAssertEqual(m.items.first { $0.title == "Float on Top" }?.state, .off)

        // The items set them.
        let domain = try XCTUnwrap(group.items.first { $0.title == "Domain" })
        XCTAssertTrue(domain.target === c)
        NSApplication.shared.sendAction(try XCTUnwrap(domain.action), to: domain.target, from: domain)
        XCTAssertEqual(s.groupBy, .domain)
        let name = try XCTUnwrap(sort.items.first { $0.title == "Name" })
        NSApplication.shared.sendAction(try XCTUnwrap(name.action), to: name.target, from: name)
        XCTAssertEqual(s.sortKey, .name)
        let local = try XCTUnwrap(m.items.first { $0.title == "Show Local Network" })
        let before = s.includeLocalNetwork
        NSApplication.shared.sendAction(try XCTUnwrap(local.action), to: local.target, from: local)
        XCTAssertEqual(s.includeLocalNetwork, !before)
        let float = try XCTUnwrap(m.items.first { $0.title == "Float on Top" })
        NSApplication.shared.sendAction(try XCTUnwrap(float.action), to: float.target, from: float)
        XCTAssertTrue(s.floatOnTop)
    }
}
