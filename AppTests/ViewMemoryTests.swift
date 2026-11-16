import XCTest
import SwiftUI
import AppKit
@testable import Rat

/// Views redrawn on every ledger pass must not grow: each pass here republishes the ledger, as the 1.5 s timer does,
/// and the memory SwiftUI holds for the view stays flat once it has settled.
@MainActor
final class ViewMemoryTests: XCTestCase {
    private func ledger() -> Ledger {
        let l = Ledger(directory: FileManager.default.temporaryDirectory.appendingPathComponent("rat-viewmem-\(UUID())"))
        l.installDemoData()
        return l
    }

    /// MB malloc grew over `passes` updates after `warmup` ones.
    private func growth<V: View>(_ view: V, ledger l: Ledger, warmup: Int = 60, passes: Int = 240, size: CGSize) -> Double {
        let host = NSHostingView(rootView: view.environmentObject(l).preferredColorScheme(.dark).frame(width: size.width, height: size.height))
        host.frame = NSRect(origin: .zero, size: size)
        let window = NSWindow(contentRect: host.frame, styleMask: [.borderless], backing: .buffered, defer: false)
        window.contentView = host
        var start = 0.0
        for i in 0..<(warmup + passes) {
            if i == warmup { start = PerformanceBudgetTests.mallocMB() }
            autoreleasepool {
                let now = Date()
                l.history.append(TrafficPoint(date: now, rx: Double((i * 7919) % 50_000), tx: Double((i * 104_729) % 9_000)))
                if l.history.count > 200 { l.history.removeFirst(l.history.count - 200) }
                l.objectWillChange.send()
                RunLoop.main.run(until: Date().addingTimeInterval(0.01))
                host.layoutSubtreeIfNeeded()
                host.display()
            }
        }
        return PerformanceBudgetTests.mallocMB() - start
    }

    func testTrafficChartStaysFlat() {
        let l = ledger()
        let grown = growth(TrafficChart(range: .fiveMinutes), ledger: l, size: CGSize(width: 380, height: 120))
        print("chart: +\(String(format: "%.2f", grown)) MB over 240 passes")
        XCTAssertLessThan(grown, 5, "the chart's marks are reused, not added each pass (conditional marks grew 321 MB)")
    }

    func testRowsStayFlat() {
        let l = ledger()
        let view = VStack(spacing: 0) { ForEach(l.apps) { ProcessRow(app: $0, selection: .constant(nil), open: true) } }
        let grown = growth(view, ledger: l, size: CGSize(width: 400, height: 700))
        print("rows: +\(String(format: "%.2f", grown)) MB over 240 passes")
        XCTAssertLessThan(grown, 5)
    }

    func testSummaryStaysFlat() {
        let l = ledger()
        let grown = growth(SummaryInspector(), ledger: l, size: CGSize(width: 330, height: 860))
        print("summary: +\(String(format: "%.2f", grown)) MB over 240 passes")
        XCTAssertLessThan(grown, 5)
    }
}
