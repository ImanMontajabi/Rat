import Darwin
import XCTest
@testable import RatMonitor

/// Safari's web apps (Add to Dock) are apps of their own: the program that runs them names its web app's bundle in
/// its arguments, and its WebKit helpers belong to that web app.
final class SafariWebAppTests: XCTestCase {
    static let host = "/System/Volumes/Preboot/Cryptexes/App/System/Library/CoreServices/Web App.app/Contents/MacOS/Web App"
    static let networking = "/System/Library/Frameworks/WebKit.framework/Versions/A/XPCServices/com.apple.WebKit.Networking.xpc/Contents/MacOS/com.apple.WebKit.Networking"
    static let x = "/Users/me/Applications/X.app"

    /// The host's command line as macOS starts it for a web app named X.
    static func argv(bundle: String = x, identifier: String = "com.apple.Safari.WebApp.5E77154E-E087-4E17-A38E-0A77B5B8757D") -> [String] {
        [host, "--bundlepath", bundle, "--sandboxextension", "cc8c755d;00;00000000;com.apple.app-sandbox.read;01;\(bundle.lowercased())",
         "--bundleidentifier", identifier, "--"]
    }

    func testTheHostProgramIsSafarisOwnInTheSystemOrItsCryptex() {
        XCTAssertTrue(SafariWebApp.isHost(Self.host))
        XCTAssertTrue(SafariWebApp.isHost("/System/Library/CoreServices/Web App.app/Contents/MacOS/Web App"), "the path ps shows")
        XCTAssertTrue(SafariWebApp.isHost("/System/Cryptexes/App/System/Library/CoreServices/Web App.app/Contents/MacOS/Web App"))
        XCTAssertFalse(SafariWebApp.isHost("/Users/me/System/Library/CoreServices/Web App.app/Contents/MacOS/Web App"), "a copy outside SIP")
        XCTAssertFalse(SafariWebApp.isHost("/Applications/Web App.app/Contents/MacOS/Web App"))
        XCTAssertFalse(SafariWebApp.isHost("/System/Volumes/Preboot/Cryptexes/App/System/Library/CoreServices/Web App.app/Contents/XPCServices/com.apple.Safari.ContentBlockerLoader.xpc/Contents/MacOS/com.apple.Safari.ContentBlockerLoader"))
        XCTAssertFalse(SafariWebApp.isHost(Self.networking))
    }

    func testTheWebAppIsTheBundleItsArgumentsName() {
        XCTAssertEqual(SafariWebApp.bundle(arguments: Self.argv()), Self.x)
        XCTAssertEqual(SafariWebApp.bundle(arguments: Self.argv(bundle: Self.x + "/")), Self.x, "a trailing slash")
        XCTAssertEqual(SafariWebApp.bundle(arguments: Self.argv(bundle: "/Users/me/Applications/Google Mail 2.app")), "/Users/me/Applications/Google Mail 2.app")
        // Only a Safari web app's bundle, as an absolute path that can go into a rule and the daemon's files.
        XCTAssertNil(SafariWebApp.bundle(arguments: Self.argv(identifier: "com.apple.Safari")), "not a web app")
        XCTAssertNil(SafariWebApp.bundle(arguments: Self.argv(identifier: "com.apple.Safari.WebApp.")))
        XCTAssertNil(SafariWebApp.bundle(arguments: Array(Self.argv().prefix(5)) + ["--"]), "no identifier")
        XCTAssertNil(SafariWebApp.bundle(arguments: Self.argv(bundle: "Applications/X.app")), "relative")
        XCTAssertNil(SafariWebApp.bundle(arguments: Self.argv(bundle: "/Users/me/Applications/../../../Applications/Safari.app")))
        XCTAssertNil(SafariWebApp.bundle(arguments: Self.argv(bundle: "/Users/me/Applications/X.app\n/Applications/Safari.app")), "a line break")
        XCTAssertNil(SafariWebApp.bundle(arguments: Self.argv(bundle: "/Applications/Safari.app/Contents/X.app")), "inside another app")
        XCTAssertNil(SafariWebApp.bundle(arguments: Self.argv(bundle: "/Users/me/Applications/X")), "not a bundle")
        XCTAssertNil(SafariWebApp.bundle(arguments: [Self.host, "--", "--bundlepath", Self.x, "--bundleidentifier", "com.apple.Safari.WebApp.1"]), "after --")
        XCTAssertNil(SafariWebApp.bundle(arguments: [Self.host, "--bundlepath"]))
    }

    func testTheWebAppAndItsHelpersAreOneAppOfTheirOwn() {
        // The host runs X: it is X.
        XCTAssertEqual(ProcessGrouping.owner(of: Self.host, responsiblePath: { nil }, webApp: { Self.x }), .app(bundle: Self.x, isExtension: false))
        // Its WebKit.Networking (and WebContent, the content blocker loader) answer to the host: X too.
        XCTAssertEqual(ProcessGrouping.owner(of: Self.networking, responsiblePath: { Self.x }), .app(bundle: Self.x, isExtension: false))
        // Without a web app (arguments not readable): the program's own bundle, as before.
        XCTAssertEqual(ProcessGrouping.owner(of: Self.host, responsiblePath: { nil }, webApp: { nil }).ruleKey,
                       "/System/Volumes/Preboot/Cryptexes/App/System/Library/CoreServices/Web App.app")
        // Safari's own WebKit.Networking stays Safari's, and other apps never ask for a web app.
        XCTAssertEqual(ProcessGrouping.owner(of: Self.networking, responsiblePath: { "/Applications/Safari.app/Contents/MacOS/Safari" }).ruleKey, "/Applications/Safari.app")
        XCTAssertEqual(ProcessGrouping.owner(of: "/Applications/Telegram.app/Contents/MacOS/Telegram", responsiblePath: { nil }, webApp: { XCTFail("asked"); return Self.x }).ruleKey,
                       "/Applications/Telegram.app")
    }

    /// `KERN_PROCARGS2` read for its arguments alone; the environment stays out.
    func testArgumentsLeaveTheEnvironmentOut() {
        var b: [UInt8] = [3, 0, 0, 0]
        b += Array("/bin/tool".utf8) + [0, 0, 0]
        for s in ["tool", "--bundlepath", "/Users/me/Applications/X.app", "TOKEN=secret"] { b += Array(s.utf8) + [0] }
        XCTAssertEqual(ProcessArguments.split(b)?.argv, ["tool", "--bundlepath", "/Users/me/Applications/X.app"])
        XCTAssertEqual(ProcessArguments.arguments(pid: getpid())?.first.map { ($0 as NSString).lastPathComponent.isEmpty }, false)
    }

    /// On this Mac, while a web app runs: its host and its WebKit helpers name the same bundle in ~/Applications.
    func testLiveWebAppAndItsNetworkingProcessNameTheSameBundle() throws {
        let pids = ConnectionSampler.allPIDs()
        guard let host = pids.first(where: { SafariWebApp.isHost(ConnectionSampler.path(of: $0)) }) else { throw XCTSkip("no Safari web app is running") }
        let bundle = try XCTUnwrap(SafariWebApp.bundle(pid: host), "the host names its web app")
        XCTAssertTrue(SafariWebApp.isWebAppBundle(bundle), bundle)
        let helpers = pids.filter { $0 != host && ProcessGrouping.responsiblePID(of: $0) == host }
        XCTAssertFalse(helpers.isEmpty, "WebKit works for the web app")
        for pid in helpers {
            XCTAssertEqual(ProcessGrouping.responsiblePath(of: pid), bundle, ConnectionSampler.path(of: pid))
            XCTAssertEqual(SafariWebApp.bundle(pid: pid), bundle)
            let path = ConnectionSampler.path(of: pid)
            XCTAssertEqual(ProcessGrouping.owner(of: path, responsiblePath: { ProcessGrouping.responsiblePath(of: pid) }, webApp: { SafariWebApp.bundle(pid: pid) }).ruleKey,
                           bundle, path)
        }
    }
}
