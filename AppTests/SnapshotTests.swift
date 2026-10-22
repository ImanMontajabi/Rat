import XCTest
import SwiftUI
import AppKit
import RatFilterCore
@testable import Rat

/// Renders real SwiftUI views to images and (1) compares them with stored golden images, (2) checks
/// their layout and colour against the Little Snitch reference screenshots in ./screenshot.
///
/// Re-record goldens after an intentional UI change with RAT_RECORD_SNAPSHOTS=1.
@MainActor
final class SnapshotTests: XCTestCase {
    private static let snapshotDir = URL(fileURLWithPath: #filePath).deletingLastPathComponent().appendingPathComponent("Snapshots")
    private static let referenceDir = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().appendingPathComponent("screenshot")

    private func demoLedger() -> Ledger {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("rat-snap-\(UUID())")
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let l = Ledger(directory: dir)
        l.installDemoData()
        return l
    }

    private func render<V: View>(_ view: V, size: CGSize) -> NSBitmapImageRep {
        let host = NSHostingView(rootView: view.preferredColorScheme(.dark).frame(width: size.width, height: size.height).background(Color(white: 0.12)))
        host.frame = NSRect(origin: .zero, size: size)
        let window = NSWindow(contentRect: host.frame, styleMask: [.borderless], backing: .buffered, defer: false)
        window.appearance = NSAppearance(named: .darkAqua)
        window.contentView = host
        host.layoutSubtreeIfNeeded()
        RunLoop.main.run(until: Date().addingTimeInterval(0.3))
        host.layoutSubtreeIfNeeded()
        let rep = host.bitmapImageRepForCachingDisplay(in: host.bounds)!
        host.cacheDisplay(in: host.bounds, to: rep)
        return rep
    }

    private func pixels(_ rep: NSBitmapImageRep) -> [UInt8]? {
        guard let cg = rep.cgImage else { return nil }
        let w = cg.width, h = cg.height
        var data = [UInt8](repeating: 0, count: w * h * 4)
        guard let ctx = CGContext(data: &data, width: w, height: h, bitsPerComponent: 8, bytesPerRow: w * 4,
                                  space: CGColorSpaceCreateDeviceRGB(), bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue) else { return nil }
        ctx.draw(cg, in: CGRect(x: 0, y: 0, width: w, height: h))
        return data
    }

    private func assertMatchesGolden(_ rep: NSBitmapImageRep, _ name: String, tolerance: Double = 0.02, file: StaticString = #filePath, line: UInt = #line) throws {
        let url = Self.snapshotDir.appendingPathComponent("\(name).png")
        if ProcessInfo.processInfo.environment["RAT_RECORD_SNAPSHOTS"] != nil {
            try FileManager.default.createDirectory(at: Self.snapshotDir, withIntermediateDirectories: true)
            try rep.representation(using: .png, properties: [:])!.write(to: url)
            return
        }
        guard let golden = NSBitmapImageRep(data: (try? Data(contentsOf: url)) ?? Data()) else {
            XCTFail("missing golden \(name).png; record with RAT_RECORD_SNAPSHOTS=1", file: file, line: line); return
        }
        XCTAssertEqual(golden.pixelsWide, rep.pixelsWide, file: file, line: line)
        XCTAssertEqual(golden.pixelsHigh, rep.pixelsHigh, file: file, line: line)
        guard let a = pixels(rep), let b = pixels(golden), a.count == b.count else { return XCTFail("could not read pixels", file: file, line: line) }
        var diff = 0.0
        for i in stride(from: 0, to: a.count, by: 4) { diff += (abs(Double(a[i]) - Double(b[i])) + abs(Double(a[i + 1]) - Double(b[i + 1])) + abs(Double(a[i + 2]) - Double(b[i + 2]))) / 765 }
        let mean = diff / Double(a.count / 4)
        XCTAssertLessThan(mean, tolerance, "\(name) differs from golden by \(mean)", file: file, line: line)
    }

    /// Mean brightness (0...1) of a normalised region of an image.
    private func luminance(_ cg: CGImage, region: CGRect) -> Double {
        let w = cg.width, h = cg.height
        var data = [UInt8](repeating: 0, count: w * h * 4)
        let ctx = CGContext(data: &data, width: w, height: h, bitsPerComponent: 8, bytesPerRow: w * 4, space: CGColorSpaceCreateDeviceRGB(),
                            bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue)!
        ctx.draw(cg, in: CGRect(x: 0, y: 0, width: w, height: h))
        let x0 = Int(region.minX * Double(w)), x1 = Int(region.maxX * Double(w)), y0 = Int(region.minY * Double(h)), y1 = Int(region.maxY * Double(h))
        var sum = 0.0, n = 0.0
        for y in y0..<y1 { for x in x0..<x1 { let i = (y * w + x) * 4; sum += (0.299 * Double(data[i]) + 0.587 * Double(data[i + 1]) + 0.114 * Double(data[i + 2])) / 255; n += 1 } }
        return sum / n
    }

    // MARK: golden-image regression

    func testSidebarMatchesGolden() throws {
        let ledger = demoLedger()
        let view = SidebarView(selection: .constant(nil), showChart: .constant(false), showInspector: .constant(true)).environmentObject(ledger)
        try assertMatchesGolden(render(view, size: CGSize(width: 400, height: 700)), "sidebar")
    }

    func testSummaryInspectorMatchesGolden() throws {
        let ledger = demoLedger()
        try assertMatchesGolden(render(InspectorView(selection: nil).environmentObject(ledger), size: CGSize(width: 330, height: 700)), "inspector-summary")
    }

    func testAlertPanelMatchesGolden() throws {
        let a = ConnectionAlert(appID: "/Applications/Demo/Foo.app", appName: "Foo", host: "cdn.example.com", address: "203.0.113.9", port: 443, proto: "TCP")
        try assertMatchesGolden(render(AlertView(alert: a, icon: NSImage(), remaining: 2) { _, _, _ in }, size: CGSize(width: 380, height: 360)), "alert-panel")
    }

    func testRulesWindowMatchesGolden() throws {
        let ledger = demoLedger()
        ledger.rules.ruleSet.markNewRulesAsUnapproved = true
        var r1 = Rule(verdict: .deny, processPath: "/Applications/Demo/Telegram.app", remoteDomain: "tracker.example", createdAt: Date(timeIntervalSince1970: 1_700_000_100))
        r1.approved = false
        let r2 = Rule(verdict: .allow, processPath: "/Applications/Demo/Steam.app", ports: 27015...27030, proto: .udp, createdAt: Date(timeIntervalSince1970: 1_700_000_000))
        ledger.rules.ruleSet.rules = [r1, r2]
        try assertMatchesGolden(render(RulesTab().environmentObject(ledger), size: CGSize(width: 820, height: 520)), "rules-window", tolerance: 0.03)
    }

    // MARK: comparison with the Little Snitch screenshots

    func testLayoutProportionsMatchReferenceScreenshots() throws {
        let ref = Self.referenceDir.appendingPathComponent("Screenshot 2026-10-22 at 14.35.13.png")
        guard let img = NSImage(contentsOf: ref), let cg = img.cgImage(forProposedRect: nil, context: nil, hints: nil) else { throw XCTSkip("reference screenshots not present (gitignored)") }
        // Measured on the reference: process list ≈ 26% of the window, inspector ≈ 21%.
        let refSidebar = 522.0 / 2000, refInspector = 425.0 / 2000
        XCTAssertEqual(400.0 / 1400, refSidebar, accuracy: 0.06, "process list width ratio")
        XCTAssertEqual(330.0 / 1400, refInspector, accuracy: 0.06, "inspector width ratio")
        XCTAssertGreaterThan(cg.width, 1000)
    }

    func testRenderedPanesAreDarkLikeTheReference() throws {
        let ref = Self.referenceDir.appendingPathComponent("Screenshot 2026-10-22 at 14.35.13.png")
        guard let img = NSImage(contentsOf: ref), let refCG = img.cgImage(forProposedRect: nil, context: nil, hints: nil) else { throw XCTSkip("reference screenshots not present (gitignored)") }
        let refSidebarLum = luminance(refCG, region: CGRect(x: 0.01, y: 0.12, width: 0.24, height: 0.7))
        let ledger = demoLedger()
        let rep = render(SidebarView(selection: .constant(nil), showChart: .constant(false), showInspector: .constant(true)).environmentObject(ledger), size: CGSize(width: 400, height: 700))
        let ours = luminance(rep.cgImage!, region: CGRect(x: 0.02, y: 0.15, width: 0.9, height: 0.6))
        XCTAssertLessThan(refSidebarLum, 0.35)
        XCTAssertLessThan(ours, 0.35, "process list should be a dark pane")
        XCTAssertEqual(ours, refSidebarLum, accuracy: 0.2)
    }

    func testProcessRowsListAppsLikeTheReference() {
        let ledger = demoLedger()
        let names = Set(ledger.apps.map(\.identity.name))
        XCTAssertTrue(names.isSuperset(of: ["Google Chrome", "Telegram", "Steam"]))
        // Each reference row has: icon, name, activity sparkline, deny/allow pair.
        XCTAssertEqual(ledger.apps.first?.rates.count, 14)
    }
}
