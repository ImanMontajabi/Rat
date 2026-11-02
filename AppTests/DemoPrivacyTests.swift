import XCTest
@testable import Rat

/// Demo mode (screenshots, UI tests) shows nothing of this Mac's: not the account name, not where the Mac is.
final class DemoPrivacyTests: XCTestCase {
    func testTheDemoShowsAFixedAccountName() {
        XCTAssertEqual(Preferences.userName(demo: true), "demo")
        XCTAssertEqual(Preferences.userName(demo: false), NSUserName())
    }

    func testTheDemoPutsThisMacInAFixedPlace() {
        XCTAssertEqual(GeoService.localPoint(demo: true), GeoService.demoPoint)
        XCTAssertEqual(GeoService.demoPoint.place, "🇩🇪 Berlin, Germany")
        // Outside demo mode the time zone decides, as before ("UTC" on CI runners is no place).
        if TimeZone.current.identifier.contains("/") { XCTAssertNotNil(GeoService.localPoint(demo: false)) }
    }
}
