import XCTest
import AppKit
@testable import Rat

/// The matte refinements: the chart's log scale, Top Domains' names before addresses, the map's short city names
/// and its labels that never pile up, and the tiles that stand in for icons a row has not got.
@MainActor
final class MatteRefinementsTests: XCTestCase {
    // MARK: chart

    func testChartLevelsKeepQuietTrafficVisibleNextToABurst() {
        let burst = 15_000_000.0
        XCTAssertEqual(ChartLayout.level(0, peak: burst), 0, "no traffic, no bar")
        XCTAssertEqual(ChartLayout.level(burst, peak: burst), 1, "the tallest bucket fills the half")
        let medium = ChartLayout.level(50_000, peak: burst)
        XCTAssertGreaterThan(medium, 0.35, "a 50 KB bucket stays a real bar next to 15 MB (a square root left 6 %)")
        XCTAssertLessThan(medium, 0.5)
        XCTAssertEqual(ChartLayout.level(10, peak: burst), ChartLayout.minimumLevel, "a trickle is the shortest bar, never silence")
        let levels = [1_000.0, 10_000, 100_000, 1_000_000, burst].map { ChartLayout.level($0, peak: burst) }
        XCTAssertEqual(levels, levels.sorted(), "more traffic is never shorter")
    }

    func testChartLayoutDrawsLevelsBetweenZeroAndOne() {
        let l = Ledger(directory: FileManager.default.temporaryDirectory.appendingPathComponent("rat-matte-\(UUID())"))
        let now = Date()
        l.history = (0..<200).map { (i: Int) -> TrafficPoint in
            let rx: Double = i == 100 ? 15_000_000 : (i % 7 == 0 ? 0 : 40_000)
            let tx: Double = i % 3 == 0 ? 0 : 5_000
            return TrafficPoint(date: now.addingTimeInterval(-Double(200 - i) * 1.5), rx: rx, tx: tx)
        }
        let layout = l.chartLayout(.fiveMinutes, now: now)
        XCTAssertEqual(layout.peak, 1.1)
        XCTAssertTrue(layout.bars.allSatisfy { (0...1).contains($0.rx) && (0...1).contains($0.tx) })
        XCTAssertEqual(layout.bars.map(\.rx).max(), 1, "the burst")
        let quiet = layout.bars.filter { $0.rx > 0 && $0.rx < 1 }.map(\.rx)
        XCTAssertGreaterThan(quiet.min() ?? 0, 0.3, "everything beside the burst is still a visible column")
    }

    func testChartTimesAreHoursAndMinutes() {
        let l = Ledger(directory: FileManager.default.temporaryDirectory.appendingPathComponent("rat-matte-\(UUID())"))
        var c = DateComponents(); c.year = 2026; c.month = 11; c.day = 16; c.hour = 18; c.minute = 5; c.second = 42
        let date = Calendar.current.date(from: c)!
        XCTAssertEqual(l.chartLayout(.fiveMinutes).label(date), "18:05", "no seconds, no AM/PM, in any locale")
        XCTAssertEqual(l.chartLayout(.day).label(date), "18:05")
        XCTAssertNotEqual(l.chartLayout(.week).label(date), "18:05", "the week shows days")
    }

    func testChartTimesNeverRepeat() {
        let end = Date(timeIntervalSinceReferenceDate: 800_000_000 + 37)
        func layout(_ span: TimeInterval, clock: Bool = true) -> ChartLayout {
            ChartLayout(bars: [], start: end.addingTimeInterval(-span), end: end, peak: 1.1, labelFormat: .dateTime, clock: clock)
        }
        for span in [65.0, 90, 180, 300, 3600, 86_400] {
            let ticks = layout(span).ticks()
            let labels = ticks.map { layout(span).label($0) }
            XCTAssertEqual(Set(labels).count, labels.count, "no label twice for \(span) s: \(labels)")
            XCTAssertLessThanOrEqual(ticks.count, 5)
            XCTAssertTrue(ticks.allSatisfy { $0 > end.addingTimeInterval(-span) && $0 < end }, "inside the chart")
            XCTAssertTrue(ticks.allSatisfy { Int($0.timeIntervalSinceReferenceDate) % 60 == 0 }, "whole minutes")
        }
        XCTAssertGreaterThanOrEqual(layout(300).ticks().count, 3, "five minutes: a label a minute")
        XCTAssertLessThanOrEqual(layout(65).ticks().count, 1, "a minute after launch: one label, not four of the same")
        XCTAssertTrue((3...4).contains(layout(604_800, clock: false).ticks().count), "the week: every other midnight")
    }

    // MARK: summary

    func testTopDomainsShowNamesBeforeAddresses() {
        let tally = [(name: "2001:4860:4829:7800::", count: 9), (name: "fe80::1", count: 5), (name: "example.com", count: 3),
                     (name: "203.0.113.4", count: 2), (name: "example.org", count: 1)]
        XCTAssertEqual(Ledger.topDomains(tally).map(\.name), ["example.com", "example.org"], "two a group, names first")
        XCTAssertEqual(Ledger.topDomains(tally, limit: 3).map(\.name), ["example.com", "example.org", "2001:4860:4829:7800::"],
                       "an address only where a name leaves room")
        XCTAssertEqual(Ledger.topDomains([(name: "203.0.113.4", count: 2)]).map(\.name), ["203.0.113.4"], "only addresses: still shown")
    }

    // MARK: map

    func testMapLabelsLeaveOutTheDistrict() {
        XCTAssertEqual(GeoPoint.shortCity("Cork (Hollyhill Industrial Estate)"), "Cork")
        XCTAssertEqual(GeoPoint.shortCity("Atlanta (Buckhead)"), "Atlanta")
        XCTAssertEqual(GeoPoint.shortCity("Düsseldorf"), "Düsseldorf")
        XCTAssertEqual(GeoPoint.shortCity("(Unknown)"), "(Unknown)", "nothing left: the name as it is")
    }

    func testMapLabelsNeverPileUp() {
        let size = CGSize(width: 60, height: 18)
        func item(_ id: String, _ x: CGFloat, _ y: CGFloat, priority: Int = 0) -> MapLabels.Item {
            MapLabels.Item(id: id, text: id, anchor: CGPoint(x: x, y: y), pinRadius: 8, priority: priority)
        }
        let apart = MapLabels.layout([item("London", 100, 100), item("Madrid", 300, 300)], measure: { _ in size })
        XCTAssertEqual(apart.map(\.key), ["London", "Madrid"])
        XCTAssertEqual(apart[0].frame.minY, 100 + 8 + MapLabels.spacing, "under its pin")
        XCTAssertEqual(apart[0].frame.midX, 100, "centred on it")

        let cluster = MapLabels.layout([item("Brussels", 100, 100), item("Amsterdam", 120, 104), item("Düsseldorf", 140, 102, priority: 2)],
                                       measure: { _ in size })
        XCTAssertEqual(cluster.map(\.key), ["Düsseldorf"], "the chosen place keeps its label; its neighbours give way")

        let overPin = MapLabels.layout([item("Paris", 100, 100), item("Lyon", 100, 125)], measure: { _ in size })
        XCTAssertEqual(overPin.map(\.key), ["Lyon"], "Paris's label would cover Lyon's pin just below it, so only Lyon's is shown")
    }

    // MARK: icons

    func testRowsWithoutAnIconGetATile() {
        typealias T = AppIdentity.IconTile
        XCTAssertEqual(AppIdentity.tile(id: "macOS", bundlePath: nil, isSystem: true), T.mac)
        XCTAssertEqual(AppIdentity.tile(id: "/opt/homebrew/bin/gh", bundlePath: nil, isSystem: false), T.tool)
        XCTAssertEqual(AppIdentity.tile(id: "/usr/bin/curl", bundlePath: nil, isSystem: false), T.tool)
        XCTAssertEqual(AppIdentity.tile(id: "/usr/libexec/rapportd", bundlePath: nil, isSystem: false), T.service)
        let ids = "/System/Library/PrivateFrameworks/IDS.framework/identityservicesd.app"
        XCTAssertEqual(AppIdentity.tile(id: ids, bundlePath: ids, isSystem: false, hasIcon: { _ in false }), T.service, "a system bundle with no icon")
        XCTAssertEqual(AppIdentity.tile(id: "/Applications/Demo/Foo.app", bundlePath: "/Applications/Demo/Foo.app", isSystem: false, hasIcon: { _ in false }), T.app)
        XCTAssertNil(AppIdentity.tile(id: "/Applications/Foo.app", bundlePath: "/Applications/Foo.app", isSystem: false, hasIcon: { _ in true }), "an app's own icon")
        XCTAssertNil(AppIdentity.tile(id: "/Applications/Foo.app/x.appex#ext", bundlePath: "/Applications/Foo.app/x.appex", isSystem: false, isExtension: true,
                                      hasIcon: { _ in false }), "an extension shows what Finder shows")
        XCTAssertNil(AppIdentity.tile(id: "/Users/me/Steam.AppBundle", bundlePath: "/Users/me/Steam.AppBundle", isSystem: false, hasIcon: { _ in false }))
    }

    func testBundleIconIsReadFromItsInfoPlist() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("rat-icon-\(UUID())")
        addTeardownBlock { try? FileManager.default.removeItem(at: dir) }
        for (name, info) in [("With.app", ["CFBundleIconFile": "AppIcon"]), ("Without.app", ["CFBundleName": "Without"])] {
            let contents = dir.appendingPathComponent(name).appendingPathComponent("Contents")
            try FileManager.default.createDirectory(at: contents, withIntermediateDirectories: true)
            XCTAssertTrue((info as NSDictionary).write(to: contents.appendingPathComponent("Info.plist"), atomically: true))
        }
        XCTAssertTrue(AppIdentity.bundleHasIcon(dir.appendingPathComponent("With.app").path))
        XCTAssertFalse(AppIdentity.bundleHasIcon(dir.appendingPathComponent("Without.app").path))
        XCTAssertFalse(AppIdentity.bundleHasIcon(dir.appendingPathComponent("Missing.app").path))
    }

    func testTileImagesDraw() throws {
        for tile in [AppIdentity.IconTile.mac, .service, .tool, .app] {
            let image = tile.image
            XCTAssertEqual(image.size, NSSize(width: 64, height: 64))
            let rep = try XCTUnwrap(NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: 64, pixelsHigh: 64, bitsPerSample: 8, samplesPerPixel: 4,
                                                     hasAlpha: true, isPlanar: false, colorSpaceName: .deviceRGB, bytesPerRow: 0, bitsPerPixel: 0))
            NSGraphicsContext.saveGraphicsState(); NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: rep)
            image.draw(in: NSRect(x: 0, y: 0, width: 64, height: 64))
            NSGraphicsContext.restoreGraphicsState()
            let centre = try XCTUnwrap(rep.colorAt(x: 32, y: 32)), corner = try XCTUnwrap(rep.colorAt(x: 1, y: 1))
            XCTAssertEqual(corner.alphaComponent, 0, accuracy: 0.01, "\(tile): inset like an app icon")
            XCTAssertGreaterThan(centre.alphaComponent, 0.9, "\(tile): a filled tile with its symbol")
        }
    }
}
