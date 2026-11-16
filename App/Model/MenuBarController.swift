import AppKit
import SwiftUI
import RatFilterCore

/// Opens SwiftUI windows from AppKit code (the status item). Set by the monitor window on appear.
@MainActor
enum WindowOpener {
    static var open: ((String) -> Void)?
}

/// The menu bar extra: live throughput next to the icon. A click opens the Control Center panel
/// (`ControlCenterPanel`, in a popover); a right-click or Control-click opens the classic menu (profile, mode, windows).
@MainActor
final class MenuBarController: NSObject, NSMenuDelegate, NSPopoverDelegate {
    private let item = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
    private let ledger: Ledger
    private var rules: RulesModel { ledger.rules }
    private let menu = NSMenu()
    private let popover = NSPopover()
    var isPanelShown: Bool { popover.isShown }

    init(ledger: Ledger) {
        self.ledger = ledger
        super.init()
        item.button?.image = NSImage(systemSymbolName: "network", accessibilityDescription: "Rat")
        item.button?.imagePosition = .imageLeading
        item.button?.font = .monospacedDigitSystemFont(ofSize: 10, weight: .regular)
        item.button?.target = self
        item.button?.action = #selector(clicked(_:))
        item.button?.sendAction(on: [.leftMouseUp, .rightMouseUp])
        item.button?.setAccessibilityIdentifier("rat-status-item")
        menu.delegate = self
        popover.behavior = .transient
        popover.animates = true
        popover.appearance = NSAppearance(named: .darkAqua)
        popover.delegate = self
        update()
    }

    @objc private func clicked(_ sender: NSStatusBarButton) {
        let event = NSApp.currentEvent
        if event?.type == .rightMouseUp || event?.modifierFlags.contains(.control) == true {
            popover.performClose(nil)
            // The status item's own placement (right under the icon, never scrolled): attach the menu for this click only.
            item.menu = menu
            sender.performClick(nil)
            item.menu = nil
        } else {
            togglePanel()
        }
    }

    // MARK: panel

    func togglePanel() {
        if popover.isShown { popover.performClose(nil) } else { showPanel() }
    }

    /// Builds the panel each time it opens and drops it on close (`popoverDidClose`): closed, it costs nothing,
    /// and nothing observes the ledger for it.
    func showPanel() {
        guard let button = item.button, item.isVisible, button.window != nil else { return }
        show(relativeTo: button.bounds, of: button)
    }

    #if DEBUG
    /// `RAT_OPEN=panel`: the panel at launch, for screenshots and UI tests. A menu bar too full for one more icon
    /// (the UI tests' second Rat) has no window for it, so then the panel hangs from the monitor window's top right.
    func showPanelAtLaunch() {
        if let w = item.button?.window, w.isVisible, w.occlusionState.contains(.visible) { showPanel(); return }
        guard let view = NSApp.windows.first(where: { $0.isVisible && $0.title == "Network Monitor" })?.contentView else { return }
        show(relativeTo: NSRect(x: view.bounds.maxX - 60, y: view.bounds.maxY - 8, width: 1, height: 1), of: view)
    }
    #endif

    private func show(relativeTo rect: NSRect, of view: NSView) {
        let panel = ControlCenterPanel(rules: ledger.rules, enforcer: ledger.enforcer, alerts: ledger.alerts,
                                       open: { [weak self] id in self?.open(id) }, quit: { NSApp.terminate(nil) })
            .environmentObject(ledger)
        let host = NSHostingController(rootView: panel)
        host.sizingOptions = [.preferredContentSize]
        popover.contentViewController = host
        popover.show(relativeTo: rect, of: view, preferredEdge: .minY)
        // Key without bringing Rat's windows forward: Escape closes, Tab moves between the controls.
        popover.contentViewController?.view.window?.makeKey()
    }

    func popoverDidClose(_ notification: Notification) { popover.contentViewController = nil }

    private func open(_ id: String) {
        popover.performClose(nil)
        NSApp.activate(ignoringOtherApps: true)
        WindowOpener.open?(id)
    }

    /// Two-line throughput like "↑ 12 KB/s ↓ 1.2 MB/s", plus a moon while a Silent Mode is active.
    func update() {
        let settings = AppSettings.shared
        item.isVisible = settings.showInMenuBar
        let silent = settings.silentModeSymbol && rules.silentMode != .off
        item.button?.image = NSImage(systemSymbolName: silent ? "moon.fill" : "network", accessibilityDescription: "Rat")
        guard settings.numericRates else { item.button?.attributedTitle = NSAttributedString(string: ""); return }
        let up = settings.formatRate(ledger.rateOut), down = settings.formatRate(ledger.rateIn)
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
            let title = m == .off ? "Alert" : m == .allow ? "Silent Allow" : "Silent Deny"
            let i = NSMenuItem(title: title, action: #selector(pickMode(_:)), keyEquivalent: "")
            i.target = self; i.representedObject = m.rawValue
            i.state = rules.silentMode == m ? .on : .off
            menu.addItem(i)
        }
        menu.addItem(.separator())
        if ledger.alerts.pendingCount > 0 { menu.addItem(header("\(ledger.alerts.pendingCount) connection alert(s) waiting")) }
        if rules.unapprovedCount > 0 { menu.addItem(header("\(rules.unapprovedCount) rule(s) to review")) }
        add(menu, "Open Network Monitor", #selector(openMonitor))
        add(menu, "Rules…", #selector(openRules))
        add(menu, "Settings…", #selector(openSettings))
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
    @objc private func openSettings() { NSApp.activate(ignoringOtherApps: true); WindowOpener.open?("settings") }
    @objc private func quit() { NSApp.terminate(nil) }
}
