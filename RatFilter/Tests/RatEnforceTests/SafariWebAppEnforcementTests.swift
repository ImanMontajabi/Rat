import XCTest
@testable import RatEnforce
import RatMonitor

/// The daemon groups a Safari web app as Rat's list does: a ✗ on one web app cuts that web app (its host and its
/// WebKit.Networking), not the other web apps and not Safari.
final class SafariWebAppEnforcementTests: XCTestCase {
    let host = "/System/Volumes/Preboot/Cryptexes/App/System/Library/CoreServices/Web App.app/Contents/MacOS/Web App"
    let networking = "/System/Library/Frameworks/WebKit.framework/Versions/A/XPCServices/com.apple.WebKit.Networking.xpc/Contents/MacOS/com.apple.WebKit.Networking"
    let x = "/Users/me/Applications/X.app", mail = "/Users/me/Applications/Google Mail.app"

    func testADeniedWebAppIsCutAndNoOtherOne() {
        let d = DeniedApps(text: x + "\n")
        XCTAssertEqual(d.entry(for: host, responsiblePath: { nil }, webApp: { self.x }), x, "the host running X")
        XCTAssertNil(d.entry(for: host, responsiblePath: { nil }, webApp: { self.mail }), "the host running another web app")
        XCTAssertEqual(d.entry(for: networking, responsiblePath: { self.x }), x, "X's WebKit.Networking")
        XCTAssertNil(d.entry(for: networking, responsiblePath: { self.mail }))
        XCTAssertNil(d.entry(for: networking, responsiblePath: { "/Applications/Safari.app/Contents/MacOS/Safari" }), "Safari's own")
        XCTAssertFalse(DeniedApps(text: "/Applications/Safari.app\n").matches(path: host, responsiblePath: { nil }, webApp: { self.x }), "denying Safari is not denying X")
    }

    /// A deny on the program's own bundle (a rule from before web apps had names) is not a deny on every web app:
    /// Rat's list no longer has that app, so the daemon must not cut what Rat shows allowed.
    func testTheProgramsOwnBundleNoLongerStandsForEveryWebApp() {
        let d = DeniedApps(text: "/System/Volumes/Preboot/Cryptexes/App/System/Library/CoreServices/Web App.app\n")
        XCTAssertNil(d.entry(for: host, responsiblePath: { nil }, webApp: { self.x }))
        XCTAssertNotNil(d.entry(for: host, responsiblePath: { nil }, webApp: { nil }), "unknown web app: as before")
    }
}
