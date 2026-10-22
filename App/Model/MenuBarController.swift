import AppKit
import SwiftUI
import RatFilterCore

/// Opens SwiftUI windows from AppKit code (the status item). Set by the monitor window on appear.
@MainActor
enum WindowOpener {
    static var open: ((String) -> Void)?
}

/// The menu bar extra: live throughput, profile selector, silent mode and shortcuts.
@MainActor
final class MenuBarController: NSObject, NSMenuDelegate {
    private let item = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
    private let ledger: Ledger
    private var rules: RulesModel { ledger.rules }

    init(ledger: Ledger) {
        self.ledger = ledger
        super.init()
        item.button?.image = NSImage(systemSymbolName: "network", accessibilityDescription: "Rat")
        item.button?.imagePosition = .imageLeading
        item.button?.font = .monospacedDigitSystemFont(ofSize: 10, weight: .regular)
        let menu = NSMenu()
        menu.delegate = self
        item.menu = menu
        update()
    }

    /// Two-line throughput like "↑ 12 KB/s ↓ 1.2 MB/s".
    func update() {
        let up = Self.rate(ledger.rateOut), down = Self.rate(ledger.rateIn)
        let text = NSMutableAttributedString(string: "↑ \(up)\n↓ \(down)")
        let style = NSMutableParagraphStyle(); style.maximumLineHeight = 10; style.alignment = .right
        text.addAttributes([.font: NSFont.monospacedDigitSystemFont(ofSize: 9, weight: .regular), .paragraphStyle: style, .baselineOffset: -4],
                           range: NSRange(location: 0, length: text.length))
        item.button?.attributedTitle = text
    }

    static func rate(_ bytesPerSecond: Double) -> String {
        let f = ByteCountFormatter(); f.countStyle = .file; f.allowsNonnumericFormatting = false
        return f.string(fromByteCount: Int64(bytesPerSecond)) + "/s"
    }

    // MARK: menu

    func menuNeedsUpdate(_ menu: NSMenu) {
        menu.removeAllItems()
        menu.addItem(header("Profile"))
        for p in rules.ruleSet.profiles {
            let i = NSMenuItem(title: p.name, action: #selector(pickProfile(_:)), keyEquivalent: "")
            i.target = self; i.representedObject = p.id
            i.state = p.id == rules.ruleSet.activeProfileID ? .on : .off
            i.image = NSImage(systemSymbolName: p.symbol, accessibilityDescription: nil)
            menu.addItem(i)
        }
        menu.addItem(.separator())
        menu.addItem(header("Mode"))
        for m in SilentMode.allCases {
            let i = NSMenuItem(title: m.rawValue, action: #selector(pickMode(_:)), keyEquivalent: "")
            i.target = self; i.representedObject = m.rawValue
            i.state = rules.silentMode == m ? .on : .off
            menu.addItem(i)
        }
        menu.addItem(.separator())
        if ledger.alerts.pendingCount > 0 { menu.addItem(header("\(ledger.alerts.pendingCount) connection alert(s) waiting")) }
        if rules.unapprovedCount > 0 { menu.addItem(header("\(rules.unapprovedCount) rule(s) to review")) }
        add(menu, "Open Network Monitor", #selector(openMonitor))
        add(menu, "Rules & Profiles…", #selector(openRules))
        menu.addItem(.separator())
        add(menu, "Quit Rat", #selector(quit))
    }

    private func header(_ s: String) -> NSMenuItem {
        let i = NSMenuItem(title: s, action: nil, keyEquivalent: ""); i.isEnabled = false; return i
    }

    private func add(_ menu: NSMenu, _ title: String, _ action: Selector) {
        let i = NSMenuItem(title: title, action: action, keyEquivalent: ""); i.target = self; menu.addItem(i)
    }

    @objc private func pickProfile(_ sender: NSMenuItem) { if let id = sender.representedObject as? UUID { rules.activate(id) } }
    @objc private func pickMode(_ sender: NSMenuItem) {
        if let raw = sender.representedObject as? String, let m = SilentMode(rawValue: raw) { rules.silentMode = m }
    }
    @objc private func openMonitor() { NSApp.activate(ignoringOtherApps: true); WindowOpener.open?("monitor") }
    @objc private func openRules() { NSApp.activate(ignoringOtherApps: true); WindowOpener.open?("rules") }
    @objc private func quit() { NSApp.terminate(nil) }
}
