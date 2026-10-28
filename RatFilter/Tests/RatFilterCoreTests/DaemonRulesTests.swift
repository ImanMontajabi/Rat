import XCTest
@testable import RatFilterCore

/// The rules the root daemon follows itself (`deny-rules.json`): it must deny only what Rat's pass denies.
final class DaemonRulesTests: XCTestCase {
    let app = "/Applications/Foo.app"
    let main = "/Applications/Foo.app/Contents/MacOS/Foo"
    let updater = "/Applications/Foo.app/Contents/MacOS/Foo Updater"

    func judge(_ rules: [Rule], names: [String: String] = [:], signatures: [String: DaemonRules.Signature]? = nil, local: String = "") -> SocketJudge {
        SocketJudge(DaemonRules(rules: rules, names: names, signatures: signatures ?? [app: .init(signingID: "com.foo", teamID: "TEAM1")], localRanges: local))
    }

    func testAProcessDenyCutsEverySocketOfThatProcessOnly() {
        let j = judge([Rule(verdict: .deny, processPath: app, executable: updater, listLevel: .process)])
        XCTAssertTrue(j.watches(app: app, executable: updater))
        XCTAssertTrue(j.denies(app: app, executable: updater, address: "203.0.113.5", port: 443, proto: .tcp))
        XCTAssertTrue(j.denies(app: app, executable: updater, address: "", port: 0, proto: .udp), "an unconnected socket too")
        XCTAssertTrue(j.denies(app: app, executable: updater, address: "192.168.1.20", port: 80, proto: .tcp), "a ✗ covers the local network, like an app's")
        XCTAssertFalse(j.denies(app: app, executable: main, address: "203.0.113.5", port: 443, proto: .tcp))
    }

    func testAConnectionDenyByAddressPortAndProtocol() {
        let j = judge([Rule(verdict: .deny, processPath: app, executable: main, listLevel: .connection, remoteAddress: "2001:db8::20", ports: 443...443, proto: .udp)])
        XCTAssertTrue(j.denies(app: app, executable: main, address: "2001:db8::20", port: 443, proto: .udp))
        XCTAssertFalse(j.denies(app: app, executable: main, address: "2001:db8::20", port: 443, proto: .tcp))
        XCTAssertFalse(j.denies(app: app, executable: main, address: "2001:db8::21", port: 443, proto: .udp))
        XCTAssertFalse(j.denies(app: app, executable: main, address: "", port: 0, proto: .udp), "not connected: it may never go there")
    }

    /// A connection ✗ on a named row names the server; the daemon follows it for the addresses Rat named so.
    func testAConnectionDenyByNameNeedsRatsName() {
        let rule = Rule(verdict: .deny, processPath: app, executable: main, listLevel: .connection, remoteHost: "ads.example.com", ports: 443...443, proto: .tcp)
        let j = judge([rule], names: ["203.0.113.7": "ads.example.com", "203.0.113.8": "www.example.com", "203.0.113.9": ""])
        XCTAssertTrue(j.denies(app: app, executable: main, address: "203.0.113.7", port: 443, proto: .tcp))
        XCTAssertFalse(j.denies(app: app, executable: main, address: "203.0.113.8", port: 443, proto: .tcp))
        XCTAssertFalse(j.denies(app: app, executable: main, address: "203.0.113.9", port: 443, proto: .tcp), "no name")
        XCTAssertFalse(j.denies(app: app, executable: main, address: "203.0.113.10", port: 443, proto: .tcp), "not named yet: Rat's pass decides")
    }

    /// An app ✗ with a ✓ for one connection by name: a server Rat has not named yet might be that one, so it is
    /// left to Rat's pass; a server named otherwise is cut at once.
    func testAnAllowForANameIsAssumedUntilTheNameIsKnown() {
        let rules = [Rule(verdict: .deny, processPath: app, listLevel: .app),
                     Rule(verdict: .allow, processPath: app, executable: main, listLevel: .connection, remoteHost: "api.example.com", ports: 443...443, proto: .tcp)]
        let j = judge(rules, names: ["203.0.113.7": "api.example.com", "203.0.113.8": "ads.example.com"])
        XCTAssertFalse(j.denies(app: app, executable: main, address: "203.0.113.7", port: 443, proto: .tcp))
        XCTAssertTrue(j.denies(app: app, executable: main, address: "203.0.113.8", port: 443, proto: .tcp))
        XCTAssertFalse(j.denies(app: app, executable: main, address: "203.0.113.99", port: 443, proto: .tcp), "unknown name")
        XCTAssertTrue(j.denies(app: app, executable: main, address: "203.0.113.99", port: 80, proto: .tcp), "the allow is for port 443 only")
        XCTAssertTrue(j.denies(app: app, executable: updater, address: "203.0.113.99", port: 443, proto: .tcp), "and for the main process only")
    }

    func testAProcessAllowUnderAnAppDeny() {
        let j = judge([Rule(verdict: .deny, processPath: app, listLevel: .app), Rule(verdict: .allow, processPath: app, executable: updater, listLevel: .process)])
        XCTAssertTrue(j.denies(app: app, executable: main, address: "203.0.113.5", port: 443, proto: .tcp))
        XCTAssertFalse(j.denies(app: app, executable: updater, address: "203.0.113.5", port: 443, proto: .tcp))
        XCTAssertFalse(j.denies(app: app, executable: updater, address: "", port: 0, proto: .udp))
    }

    /// Rules from alerts or the Rules window do not judge connections inside the local network (Rat's pass skips
    /// them), and the user's own local ranges count.
    func testRulesFromAlertsLeaveTheLocalNetworkAlone() {
        let rules = [Rule(verdict: .deny, processPath: app, ports: 80...80)]
        let j = judge(rules, local: "100.64.0.0/10")
        XCTAssertTrue(j.denies(app: app, executable: main, address: "203.0.113.5", port: 80, proto: .tcp))
        for lan in ["192.168.1.20", "10.0.0.2", "172.20.1.1", "fd00::1", "100.70.0.1"] {
            XCTAssertFalse(j.denies(app: app, executable: main, address: lan, port: 80, proto: .tcp), lan)
        }
    }

    func testAnAnyProcessDenyStillOverridesAProcessAllow() {
        let rules = [Rule(verdict: .deny, processPath: app, executable: updater, listLevel: .process),
                     Rule(verdict: .allow, processPath: app, executable: main, listLevel: .process),
                     Rule(verdict: .deny, remoteAddress: "203.0.113.66")]
        let j = judge(rules)
        XCTAssertTrue(j.denies(app: app, executable: main, address: "203.0.113.66", port: 443, proto: .tcp))
        XCTAssertFalse(j.denies(app: app, executable: main, address: "203.0.113.5", port: 443, proto: .tcp))
        XCTAssertFalse(j.watches(app: "/Applications/Other.app", executable: "/Applications/Other.app/Contents/MacOS/Other"),
                       "a deny for any process is left to Rat's pass: it would mean reading every process")
    }

    func testCodeSignatureRules() {
        let rules = [Rule(verdict: .deny, processPath: app, ports: 443...443), Rule(verdict: .allow, processPath: app, signingID: "com.foo", ports: 443...443, proto: .tcp)]
        XCTAssertFalse(judge(rules).denies(app: app, executable: main, address: "203.0.113.5", port: 443, proto: .tcp), "the signed app is allowed")
        XCTAssertTrue(judge(rules, signatures: [app: .init(signingID: "com.evil", teamID: nil)]).denies(app: app, executable: main, address: "203.0.113.5", port: 443, proto: .tcp))
        XCTAssertFalse(judge(rules, signatures: [:]).denies(app: app, executable: main, address: "203.0.113.5", port: 443, proto: .tcp),
                       "an unknown signature might be the allowed one")
    }

    func testWatchesTheAppsAndProcessesDenyRulesName() {
        let j = judge([Rule(verdict: .deny, processPath: "/usr/sbin/mDNSResponder"), Rule(verdict: .deny, processPath: app, executable: updater, listLevel: .process),
                       Rule(verdict: .allow, processPath: "/Applications/Bar.app")])
        XCTAssertTrue(j.watches(app: "macOS", executable: "/usr/sbin/mDNSResponder"), "a system service by its path")
        XCTAssertTrue(j.watches(app: app, executable: main), "the app's other processes are read too (a rule for the app may decide)")
        XCTAssertFalse(j.watches(app: "/Applications/Bar.app", executable: "/Applications/Bar.app/Contents/MacOS/Bar"), "only an allow")
        XCTAssertFalse(j.watches(app: "macOS", executable: "/usr/libexec/trustd"))
        var off = Rule(verdict: .deny, processPath: "/Applications/Baz.app"); off.enabled = false
        XCTAssertFalse(judge([off]).watches(app: "/Applications/Baz.app", executable: "/Applications/Baz.app/Contents/MacOS/Baz"))
    }

    /// A decision with something unknown is a deny only when it is a deny whatever the unknown part is.
    func testDecideWithUnknownsIsADenyOnlyForSure() {
        let c = Connection(process: ProcessIdentity(path: app), executable: main, address: "203.0.113.5", port: 443, proto: .tcp)
        let denyDomain = Rule(verdict: .deny, processPath: app, remoteDomain: "ads.example.com")
        let allowDomain = Rule(verdict: .allow, processPath: app, remoteDomain: "example.com")
        let denyApp443 = Rule(verdict: .deny, processPath: app, ports: 443...443)
        XCTAssertEqual(RuleEngine(rules: [denyDomain], defaultVerdict: .allow).decide(c, unknown: .host).verdict, .allow, "the name may be another one")
        XCTAssertEqual(RuleEngine(rules: [denyApp443, allowDomain], defaultVerdict: .allow).decide(c, unknown: .host).verdict, .allow, "the name may be allowed")
        XCTAssertEqual(RuleEngine(rules: [denyApp443, allowDomain], defaultVerdict: .allow).decide(c).verdict, .deny, "with no name the port rule decides")
        XCTAssertEqual(RuleEngine(rules: [denyApp443, Rule(verdict: .allow, processPath: app, remoteDomain: "example.com", ports: 80...80)], defaultVerdict: .allow)
                        .decide(c, unknown: .host).verdict, .deny, "an allow for another port cannot apply")
        XCTAssertEqual(RuleEngine(rules: [], defaultVerdict: .deny).decide(c, unknown: .host).verdict, .deny, "Silent Mode is the engine's, not the daemon's")
    }

    /// Rat hands over the rules of its active profile and enabled groups; the daemon knows neither, so they apply.
    func testRulesOfRatsActiveProfileApply() {
        var r = Rule(verdict: .deny, processPath: app, executable: updater, listLevel: .process)
        r.profileID = UUID(); r.groupID = UUID()
        XCTAssertTrue(judge([r]).denies(app: app, executable: updater, address: "203.0.113.5", port: 443, proto: .tcp))
    }

    func testFileRoundTripAndTolerantDecode() throws {
        var r = Rule(verdict: .deny, processPath: app, executable: updater, listLevel: .process)
        r.createdAt = Date(timeIntervalSince1970: 1_793_000_000)
        let d = DaemonRules(rules: [r], names: ["203.0.113.7": "a.example.com"], signatures: [app: .init(signingID: "com.foo", teamID: nil)], localRanges: "100.64.0.0/10")
        XCTAssertEqual(DaemonRules.decode(try d.encoded()), d)
        XCTAssertEqual(DaemonRules.decode(Data("{}".utf8)), DaemonRules())
        XCTAssertNil(DaemonRules.decode(Data("not json".utf8)))
        XCTAssertTrue(d.hasProcessDenies)
        XCTAssertFalse(DaemonRules(rules: [Rule(verdict: .deny, remoteDomain: "example.com")]).hasProcessDenies)
    }

    /// The file scripts/verify-blocking.sh writes by hand (no ids or dates) is read like Rat's own.
    func testAHandWrittenFileIsRead() throws {
        let text = #"{"version": 1, "rules": [{"verdict": "deny", "processPath": "macOS", "executable": "/usr/bin/curl", "listLevel": "connection", "remoteHost": "proof.ovh.net", "ports": [443, 443], "proto": "tcp"}], "names": {"141.95.207.211": "proof.ovh.net"}, "signatures": {}, "localRanges": ""}"#
        let d = try XCTUnwrap(DaemonRules.decode(Data(text.utf8)))
        let j = SocketJudge(d)
        XCTAssertTrue(j.watches(app: "macOS", executable: "/usr/bin/curl"))
        XCTAssertTrue(j.denies(app: "macOS", executable: "/usr/bin/curl", address: "141.95.207.211", port: 443, proto: .tcp))
        XCTAssertFalse(j.denies(app: "macOS", executable: "/usr/bin/curl", address: "93.184.215.14", port: 443, proto: .tcp))
        XCTAssertFalse(j.denies(app: "macOS", executable: "/usr/bin/python3", address: "141.95.207.211", port: 443, proto: .tcp))
    }

    func testLocalNetwork() {
        let extra = LocalRanges(); extra.set("100.64.0.0/10")
        for a in ["127.0.0.1", "10.1.2.3", "172.16.0.1", "172.31.255.1", "192.168.0.1", "169.254.1.1", "::1", "fe80::1", "fd12::1", "100.64.0.1"] {
            XCTAssertTrue(LocalNetwork.contains(a, extra: extra), a)
        }
        for a in ["172.15.0.1", "172.32.0.1", "8.8.8.8", "2001:db8::1", "172.", "100.128.0.1"] {
            XCTAssertFalse(LocalNetwork.contains(a, extra: extra), a)
        }
    }
}
