import XCTest
import RatEnforce
@testable import Rat

/// After an update of Rat, a helper that is not the one in the app's bundle (installed, or still running) asks for
/// Update Helper, by its SHA-256 and not by a version number; and Windscribe's tunnels are listed under Windscribe.
@MainActor
final class HelperUpdateTests: XCTestCase {
    private func tempDir() throws -> URL {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("rat-helper-\(UUID())")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        addTeardownBlock { try? FileManager.default.removeItem(at: dir) }
        return dir
    }

    private let plist = "<string>--repair</string>"

    private func status(digest: String?) -> EnforcerStatus {
        EnforcerStatus(pid: 1, updated: Date(), pfEnabled: true, anchorHooked: true, deniedApps: [:], blockedPorts: 0, executableSHA256: digest)
    }

    func testReasonComparesDigestsNotVersions() {
        XCTAssertNil(Enforcer.outdatedReason(plist: plist, bundled: "aa", installed: "aa", status: status(digest: "aa")))
        XCTAssertNil(Enforcer.outdatedReason(plist: plist, bundled: "aa", installed: "aa", status: nil), "the daemon is not running: shown on its own")
        XCTAssertTrue(Enforcer.outdatedReason(plist: plist, bundled: "aa", installed: "bb", status: status(digest: "bb"))?.contains("installed helper is not the one") ?? false)
        XCTAssertTrue(Enforcer.outdatedReason(plist: plist, bundled: "aa", installed: nil, status: nil)?.contains("installed helper") ?? false, "a missing binary")
        XCTAssertTrue(Enforcer.outdatedReason(plist: plist, bundled: "aa", installed: "aa", status: status(digest: "bb"))?.contains("not restarted") ?? false)
        XCTAssertTrue(Enforcer.outdatedReason(plist: plist, bundled: "aa", installed: "aa", status: status(digest: nil))?.contains("not restarted") ?? false,
                      "a daemon from before the digest")
        XCTAssertTrue(Enforcer.outdatedReason(plist: "<string>--denied</string>", bundled: "aa", installed: "aa", status: nil)?.contains("older version") ?? false)
        XCTAssertNil(Enforcer.outdatedReason(plist: plist, bundled: nil, installed: "bb", status: nil), "nothing bundled to compare with")
    }

    /// The installed file is hashed and compared with the bundled one, and the daemon's status with both.
    func testEnforcerReportsAnUpdateWhenTheInstalledOrRunningHelperDiffers() throws {
        let dir = try tempDir()
        let bundled = dir.appendingPathComponent("rat-enforcerd"), installed = dir.appendingPathComponent("installed"), plistURL = dir.appendingPathComponent("pf.plist")
        try Data("new helper".utf8).write(to: bundled)
        try Data("new helper".utf8).write(to: installed)
        try Data(plist.utf8).write(to: plistURL)
        let statusURL = dir.appendingPathComponent("status.json")
        func writeStatus(_ digest: String?) throws {
            let enc = JSONEncoder()
            enc.dateEncodingStrategy = .secondsSince1970
            try enc.encode(status(digest: digest)).write(to: statusURL)
        }
        let digest = try XCTUnwrap(FileDigest.sha256(atPath: bundled.path))
        try writeStatus(digest)
        let e = Enforcer(supportDirectory: dir, helperInstalled: true, statusPath: statusURL.path,
                         helperFiles: .init(plist: plistURL.path, bundled: bundled.path, installed: installed.path))
        e.refreshStatus()
        XCTAssertFalse(e.helperOutdated, e.outdatedReason ?? "")

        try writeStatus(String(repeating: "0", count: 64))   // the daemon still runs the old binary
        e.refreshStatus()
        XCTAssertTrue(e.outdatedReason?.contains("not restarted") ?? false, e.outdatedReason ?? "nil")

        try writeStatus(digest)
        try Data("old helper".utf8).write(to: installed)        // an older Rat installed it
        e.refreshStatus()
        XCTAssertTrue(e.outdatedReason?.contains("installed helper is not the one") ?? false, e.outdatedReason ?? "nil")

        try Data("new helper".utf8).write(to: installed)
        e.refreshStatus()
        XCTAssertFalse(e.helperOutdated)
    }

    func testWindscribesTunnelsAreListedUnderWindscribe() {
        for tunnel in ["windscribeamneziawg", "windscribeopenvpn", "windscribewstunnel", "windscribectrld"] {
            let id = AppIdentity.resolve(processPath: "/Library/Application Support/Windscribe/bin/" + tunnel)
            XCTAssertEqual(id.id, "/Applications/Windscribe.app", tunnel)
            XCTAssertEqual(id.ruleKey, "/Applications/Windscribe.app")
            XCTAssertEqual(id.name, "Windscribe")
        }
        XCTAssertEqual(AppIdentity.resolve(processPath: "/Library/PrivilegedHelperTools/com.windscribe.helper.macos").id, "/Applications/Windscribe.app")
        XCTAssertEqual(AppIdentity.resolve(processPath: "/Applications/Windscribe.app/Contents/MacOS/Windscribe").id, "/Applications/Windscribe.app")
    }
}
