import XCTest
@testable import RatMonitor

/// Which app a process belongs to: the same answer for Rat's list and the root daemon (`ProcessGrouping.owner`).
final class ProcessGroupingTests: XCTestCase {
    func owner(_ path: String, responsible: String? = nil) -> ProcessGrouping.Owner {
        ProcessGrouping.owner(of: path, responsiblePath: { responsible })
    }

    func testOwners() {
        XCTAssertEqual(owner("/Applications/Google Chrome.app/Contents/Frameworks/Google Chrome Framework.framework/Helpers/Google Chrome Helper.app/Contents/MacOS/Google Chrome Helper"),
                       .app(bundle: "/Applications/Google Chrome.app", isExtension: false))
        XCTAssertEqual(owner("/Applications/Foo.app/Contents/PlugIns/Share.appex/Contents/MacOS/Share"), .app(bundle: "/Applications/Foo.app", isExtension: true))
        XCTAssertEqual(owner("/Library/Application Support/Windscribe/bin/windscribewstunnel"), .app(bundle: "/Applications/Windscribe.app", isExtension: false))
        XCTAssertEqual(owner("/usr/sbin/mDNSResponder"), .system)
        XCTAssertEqual(owner("/usr/bin/curl").ruleKey, "macOS")
        XCTAssertEqual(owner("/opt/homebrew/bin/wget"), .tool("/opt/homebrew/bin/wget"))
        XCTAssertEqual(owner("/Users/me/.local/share/claude/versions/2.1.308"), .tool("/Users/me/.local/share/claude"))
    }

    func testAServiceWorkingForAnAppBelongsToIt() {
        let webkit = "/System/Library/Frameworks/WebKit.framework/Versions/A/XPCServices/com.apple.WebKit.Networking.xpc/Contents/MacOS/com.apple.WebKit.Networking"
        XCTAssertEqual(owner(webkit, responsible: "/Applications/Safari.app/Contents/MacOS/Safari"), .app(bundle: "/Applications/Safari.app", isExtension: false))
        XCTAssertEqual(owner(webkit, responsible: nil), .system)
        XCTAssertEqual(owner(webkit, responsible: "/usr/libexec/somed"), .system, "a service working for another service stays in macOS")
        var asked = false
        _ = ProcessGrouping.owner(of: "/Applications/Foo.app/Contents/MacOS/Foo", responsiblePath: { asked = true; return nil })
        XCTAssertFalse(asked, "only a service that works for others is asked about")
    }
}
