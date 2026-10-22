import XCTest
@testable import Rat

final class RatAppTests: XCTestCase {
    func testVersionComparison() {
        XCTAssertTrue(UpdateChecker.isNewer("v0.3.0", than: "0.2.0"))
        XCTAssertTrue(UpdateChecker.isNewer("1.0", than: "0.9.9"))
        XCTAssertFalse(UpdateChecker.isNewer("v0.2.0", than: "0.2.0"))
        XCTAssertFalse(UpdateChecker.isNewer("0.1.9", than: "0.2.0"))
    }

    func testAppIdentityGroupsHelpersUnderOutermostApp() {
        let helper = "/Applications/Google Chrome.app/Contents/Frameworks/Google Chrome Framework.framework/Helpers/Google Chrome Helper.app/Contents/MacOS/Google Chrome Helper"
        let id = AppIdentity.resolve(processPath: helper)
        XCTAssertEqual(id.id, "/Applications/Google Chrome.app")
        XCTAssertEqual(id.name, "Google Chrome")
    }

    func testSystemProcessesGroupAsMacOS() {
        XCTAssertEqual(AppIdentity.resolve(processPath: "/usr/libexec/rapportd").id, "macOS")
        XCTAssertTrue(AppIdentity.resolve(processPath: "/System/Library/CoreServices/Finder.app/Contents/MacOS/Finder").id.hasSuffix("Finder.app"))
    }

    func testLocalAddressDetection() {
        for a in ["127.0.0.1", "192.168.1.5", "10.0.0.2", "172.16.0.1", "172.31.255.1", "::1", "fe80::1"] { XCTAssertTrue(isLocalAddress(a), a) }
        for a in ["8.8.8.8", "172.32.0.1", "143.58.81.2"] { XCTAssertFalse(isLocalAddress(a), a) }
    }

    func testRegistrableDomain() {
        XCTAssertEqual(registrableDomain("a.b.googleusercontent.com"), "googleusercontent.com")
        XCTAssertEqual(registrableDomain("1.2.3.4"), "1.2.3.4")
    }

    func testShellQuotingNeutralisesInjection() {
        XCTAssertEqual(Enforcer.shellQuote("a'b; rm -rf /"), "'a'\\''b; rm -rf /'")
        XCTAssertEqual(Enforcer.appleScriptEscape("say \"hi\" \\"), "say \\\"hi\\\" \\\\")
    }

    /// The helper must drop everything that is not a valid IP, and quote nothing into pfctl.
    func testHelperScriptRejectsHostileBlocklist() throws {
        let script = try XCTUnwrap(Bundle(for: Self.self).path(forResource: "rat-pf-helper", ofType: "sh") ?? Bundle.main.path(forResource: "rat-pf-helper", ofType: "sh"))
        let list = FileManager.default.temporaryDirectory.appendingPathComponent("list-\(UUID()).txt")
        try "1.2.3.4\n999.1.1.1\nnot-an-ip\n2001:db8::1\n8.8.8.8; rm -rf /\n1.2.3.4\n".write(to: list, atomically: true, encoding: .utf8)
        let p = Process(); p.executableURL = URL(fileURLWithPath: "/bin/sh"); p.arguments = [script, "apply", list.path]
        p.environment = ["RAT_DRYRUN": "1"]
        let out = Pipe(); p.standardOutput = out; try p.run(); p.waitUntilExit()
        let text = String(decoding: out.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
        XCTAssertTrue(text.contains("-T replace 1.2.3.4 2001:db8::1\n"), text)
        XCTAssertFalse(text.contains("999"))
        XCTAssertFalse(text.contains("rm -rf"))
    }
}
