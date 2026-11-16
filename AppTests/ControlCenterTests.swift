import XCTest
import SwiftUI
import AppKit
import RatEnforce
import RatMonitor
import RatFilterCore
@testable import Rat

/// The menu bar panel: what it says about the firewall (never "on" without a running, current helper), the route,
/// the busy apps, what waits, and Rat's flags.
@MainActor
final class ControlCenterTests: XCTestCase {
    private func status(pf: Bool = true, hooked: Bool = true, blocked: Int = 0, loopback: Int? = nil, issue: String? = nil) -> EnforcerStatus {
        EnforcerStatus(pid: 1, updated: Date(), pfEnabled: pf, anchorHooked: hooked, deniedApps: [:], blockedPorts: blocked,
                       blockedLoopbackPorts: loopback, pfIssue: issue)
    }

    func testWithoutTheHelperRatOnlyMonitors() {
        let idle = ControlCenter.protection(helperInstalled: false, helperOutdated: false, status: nil, denying: false)
        XCTAssertEqual(idle.tone, .monitoring)
        XCTAssertEqual(idle.title, "Monitoring only")
        XCTAssertEqual(idle.fix, .installHelper)
        let denying = ControlCenter.protection(helperInstalled: false, helperOutdated: false, status: nil, denying: true)
        XCTAssertEqual(denying.tone, .warning, "a deny that is not enforced is a warning")
        XCTAssertTrue(denying.detail.contains("not enforced"))
    }

    func testTheFirewallIsOnlyOnWithARunningCurrentHelper() {
        XCTAssertEqual(ControlCenter.protection(helperInstalled: true, helperOutdated: true, status: status(), denying: false).fix, .updateHelper)
        let stopped = ControlCenter.protection(helperInstalled: true, helperOutdated: false, status: nil, denying: true)
        XCTAssertEqual(stopped.tone, .warning)
        XCTAssertEqual(stopped.title, "Firewall helper not running")
        let issue = ControlCenter.protection(helperInstalled: true, helperOutdated: false, status: status(issue: "pf is off"), denying: false)
        XCTAssertEqual(issue.tone, .warning)
        XCTAssertEqual(issue.detail, "pf is off")
        let unhooked = ControlCenter.protection(helperInstalled: true, helperOutdated: false, status: status(hooked: false), denying: true)
        XCTAssertEqual(unhooked.tone, .warning, "something to block but pf skips Rat's anchor")
        let idle = ControlCenter.protection(helperInstalled: true, helperOutdated: false, status: status(pf: false), denying: false)
        XCTAssertEqual(idle.tone, .on, "pf may rest while nothing is denied")
        XCTAssertEqual(idle.detail, "Nothing denied")
        let blocking = ControlCenter.protection(helperInstalled: true, helperOutdated: false, status: status(blocked: 2, loopback: 1), denying: true)
        XCTAssertEqual(blocking.title, "Firewall on")
        XCTAssertEqual(blocking.detail, "Blocking 3 connections")
        XCTAssertNil(blocking.fix)
        XCTAssertEqual(ControlCenter.protection(helperInstalled: true, helperOutdated: false, status: status(), denying: true).detail, "Ready to block what you deny")
    }

    func testTheRouteNamesTheTunnelAndWhereItLeads() {
        let warp = OpenWarpStatus(pid: 9, connected: true, mode: "warp", interface: "utun7", colo: "DUS", loc: "de")
        XCTAssertEqual(ControlCenter.route(internetTunnel: "utun7", tunnelNames: ["utun7": "OpenWarp"], tunnelServers: ["utun7": .country("IE")], openWarp: warp, proxies: []),
                       .vpn(name: "OpenWarp", country: "IE"), "the carrier's own country first")
        XCTAssertEqual(ControlCenter.route(internetTunnel: "utun7", tunnelNames: ["utun7": "OpenWarp"], tunnelServers: ["utun7": .unknown], openWarp: warp, proxies: []),
                       .vpn(name: "OpenWarp", country: "DE"), "OpenWarp's exit when the carrier is not placed")
        XCTAssertEqual(ControlCenter.route(internetTunnel: "utun3", tunnelNames: [:], tunnelServers: [:], openWarp: warp, proxies: []),
                       .vpn(name: "utun3", country: nil), "OpenWarp's exit only for its own tunnel")
        XCTAssertEqual(ControlCenter.route(internetTunnel: nil, tunnelNames: [:], tunnelServers: [:], openWarp: nil,
                                           proxies: [.init(kind: .https, host: "proxy.example", port: 3128)]),
                       .proxy("HTTPS proxy proxy.example:3128"))
        XCTAssertEqual(ControlCenter.route(internetTunnel: nil, tunnelNames: [:], tunnelServers: [:], openWarp: nil, proxies: []), .direct)
    }

    func testActiveAppsAreTheBusiestOfTheLastPass() {
        func app(_ name: String, rx: Double, tx: Double, local: Bool = false) -> AppEntry {
            var e = AppEntry(identity: AppIdentity.resolve(processPath: "/Applications/\(name).app/Contents/MacOS/\(name)"))
            e.rates = [(rx: 1e9, tx: 1e9), (rx: rx, tx: tx)]
            e.remotes = [RemoteHost(address: local ? "192.168.1.5" : "203.0.113.\(name.count)", host: name, port: 443, proto: "TCP")]
            return e
        }
        let apps = [app("Quiet", rx: 0, tx: 0), app("Small", rx: 10, tx: 0), app("Big", rx: 9_000, tx: 1_000), app("Lan", rx: 50_000, tx: 0, local: true)]
        XCTAssertEqual(ControlCenter.activeApps(apps, hideLocal: false).map(\.app.identity.name), ["Lan", "Big", "Small"], "now, not before: an idle app is out")
        XCTAssertEqual(ControlCenter.activeApps(apps, hideLocal: true).map(\.app.identity.name), ["Big", "Small"], "local-only apps follow the Local switch")
        XCTAssertEqual(ControlCenter.activeApps(apps, limit: 1, hideLocal: false).count, 1)
    }

    func testPendingWorkIsOneLine() {
        XCTAssertNil(ControlCenter.pending(alerts: 0, unapproved: 0))
        XCTAssertEqual(ControlCenter.pending(alerts: 1, unapproved: 0), "1 alert waiting")
        XCTAssertEqual(ControlCenter.pending(alerts: 2, unapproved: 3), "2 alerts waiting · 3 rules to review")
    }

    func testFlagsAreFramedRectanglesOfOneSize() throws {
        let de = try XCTUnwrap(Flags.image("DE", height: 12))
        XCTAssertEqual(de.size, NSSize(width: 17, height: 12))
        XCTAssertEqual(Flags.image("de", height: 12), de, "cached, case-insensitive")
        XCTAssertNotNil(Flags.image("CH", height: 12), "a square flag fills the frame too")
        XCTAssertNil(Flags.image("ZZ", height: 12))
        XCTAssertNil(Flags.image("", height: 12))
        XCTAssertNotNil(Flags.image("EU", height: 12), "the EU has one too")
        XCTAssertNil(Flags.art("../de"), "only plain region codes name a file")
        let art = try XCTUnwrap(Flags.art("DE"))
        XCTAssertEqual(art.size.width / art.size.height, 4.0 / 3.0, accuracy: 0.01, "the bundled flat artwork, not an emoji")
        // The corners are outside the rounded frame: transparent.
        let rep = try XCTUnwrap(NSBitmapImageRep(data: try XCTUnwrap(de.tiffRepresentation)))
        XCTAssertLessThan(rep.colorAt(x: 0, y: 0)?.alphaComponent ?? 1, 0.2)
        let mid = try XCTUnwrap(rep.colorAt(x: rep.pixelsWide / 2, y: rep.pixelsHigh / 2))
        XCTAssertGreaterThan(mid.alphaComponent, 0.95)
    }
}
