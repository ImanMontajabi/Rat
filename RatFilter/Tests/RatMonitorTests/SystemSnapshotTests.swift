import XCTest
@testable import RatMonitor

final class SystemSnapshotTests: XCTestCase {
    func testParsesConnectionsAndSkipsListeners() {
        let text = """
        p100
        f7
        PTCP
        n192.168.1.5:50000->17.253.1.1:443
        TST=ESTABLISHED
        f8
        PTCP
        n*:7000
        TST=LISTEN
        p200
        f3
        PUDP
        n[fe80::1]:5353->[2001:db8::2]:53
        #PS
          100 /Applications/Foo.app/Contents/MacOS/Foo
          200 /usr/sbin/mDNSResponder
        """
        let c = SystemSnapshot.parse(text)
        XCTAssertEqual(c.count, 2)
        XCTAssertEqual(c[0].pid, 100)
        XCTAssertEqual(c[0].remoteAddress, "17.253.1.1")
        XCTAssertEqual(c[0].remotePort, 443)
        XCTAssertEqual(c[0].tcpState, "ESTABLISHED")
        XCTAssertEqual(c[0].processPath, "/Applications/Foo.app/Contents/MacOS/Foo")
        XCTAssertEqual(c[1].proto, .udp)
        XCTAssertEqual(c[1].remoteAddress, "2001:db8::2")
        XCTAssertEqual(c[1].processPath, "/usr/sbin/mDNSResponder")
    }

    func testParsesRealHelperOutput() throws {
        let out = FileManager.default.temporaryDirectory.appendingPathComponent("snap-\(UUID()).txt")
        let script = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent().appendingPathComponent("App/Resources/rat-pf-helper.sh")
        let p = Process(); p.executableURL = URL(fileURLWithPath: "/bin/sh"); p.arguments = [script.path, "snapshot", out.path, ""]
        try p.run(); p.waitUntilExit()
        let c = SystemSnapshot.parse(try String(contentsOf: out, encoding: .utf8))
        XCTAssertFalse(c.isEmpty)
        XCTAssertTrue(c.allSatisfy { $0.remotePort > 0 || !$0.remoteAddress.isEmpty })
    }

    func testEmptyAndGarbageInput() {
        XCTAssertTrue(SystemSnapshot.parse("").isEmpty)
        XCTAssertTrue(SystemSnapshot.parse("garbage\n#PS\nnot a line").isEmpty)
    }
}
