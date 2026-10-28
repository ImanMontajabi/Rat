import XCTest
@testable import RatFilterCore

/// The kernel names programs loaded from a cryptex by their place in it, `ps` and lsof by the path they were started
/// by. Rat's rules come from either; the daemon sees the kernel's. Live on macOS 27: a ✗ on Safari's
/// com.apple.Safari.SearchHelper was saved with `/System/Library/…` and never matched the daemon's
/// `/System/Volumes/Preboot/Cryptexes/Incoming/OS/System/Library/…`, so nothing was blocked.
final class ProgramPathTests: XCTestCase {
    let started = "/System/Library/PrivateFrameworks/SafariShared.framework/Versions/A/XPCServices/com.apple.Safari.SearchHelper.xpc/Contents/MacOS/com.apple.Safari.SearchHelper"
    var kernel: String { "/System/Volumes/Preboot/Cryptexes/Incoming/OS" + started }
    var afterRestart: String { "/System/Volumes/Preboot/Cryptexes/OS" + started }
    let safari = "/System/Volumes/Preboot/Cryptexes/App/System/Applications/Safari.app"

    func testCanonicalSpelling() {
        XCTAssertEqual(ProgramPath.canonical(kernel), started)
        XCTAssertEqual(ProgramPath.canonical(afterRestart), started)
        XCTAssertEqual(ProgramPath.canonical("/System/Cryptexes/OS" + started), started)
        XCTAssertEqual(ProgramPath.canonical(started), started)
        XCTAssertEqual(ProgramPath.canonical(safari), "/System/Cryptexes/App/System/Applications/Safari.app")
        XCTAssertEqual(ProgramPath.canonical("/System/Cryptexes/App/usr/libexec/SafariBookmarksSyncAgent"), "/System/Cryptexes/App/usr/libexec/SafariBookmarksSyncAgent")
        XCTAssertEqual(ProgramPath.canonical("/Applications/Foo.app"), "/Applications/Foo.app")
        XCTAssertEqual(ProgramPath.canonical("/System/Volumes/Preboot/Cryptexesque/x"), "/System/Volumes/Preboot/Cryptexesque/x")
    }

    func testInsideAndSame() {
        XCTAssertTrue(ProgramPath.inside(kernel, started))
        XCTAssertTrue(ProgramPath.inside(started, afterRestart))
        XCTAssertTrue(ProgramPath.inside(safari + "/Contents/MacOS/Safari", "/System/Cryptexes/App/System/Applications/Safari.app"))
        XCTAssertFalse(ProgramPath.inside("/Applications/Foo.appx", "/Applications/Foo.app"))
        XCTAssertTrue(ProgramPath.same(kernel, afterRestart))
        XCTAssertFalse(ProgramPath.same(kernel, safari))
    }

    /// A process rule saved with either name matches the process seen under the other, in Rat's pass and in the daemon.
    func testAProcessRuleMatchesEitherName() {
        for (ruleName, seenAs) in [(started, kernel), (kernel, started), (kernel, afterRestart)] {
            let rule = Rule(verdict: .deny, processPath: safari, executable: ruleName, listLevel: .process)
            let c = Connection(process: ProcessIdentity(path: safari), executable: seenAs, address: "2a00:1450:400c:c06::8b", port: 443)
            XCTAssertTrue(rule.matches(c), "\(ruleName) vs \(seenAs)")
            let judge = SocketJudge(DaemonRules(rules: [rule]))
            XCTAssertTrue(judge.watches(app: safari, executable: seenAs))
            XCTAssertTrue(judge.denies(app: safari, executable: seenAs, address: "2a00:1450:400c:c06::8b", port: 443, proto: .tcp))
        }
        let other = Connection(process: ProcessIdentity(path: safari), executable: "/System/Volumes/Preboot/Cryptexes/Incoming/OS/System/Library/Frameworks/WebKit.framework/Versions/A/XPCServices/com.apple.WebKit.Networking.xpc/Contents/MacOS/com.apple.WebKit.Networking", address: "203.0.113.5", port: 443)
        XCTAssertFalse(Rule(verdict: .deny, processPath: safari, executable: started, listLevel: .process).matches(other), "another helper")
    }
}
