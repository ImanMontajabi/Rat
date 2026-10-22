import SwiftUI
import AppKit

final class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { false }

    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        if !flag { Task { @MainActor in WindowOpener.open?("monitor") } }
        return true
    }
}

@main
struct RatApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var delegate
    @StateObject private var ledger = Ledger()
    @State private var menuBar: MenuBarController?

    var body: some Scene {
        Window("Network Monitor", id: "monitor") {
            MonitorWindow()
                .environmentObject(ledger)
                .frame(minWidth: 1000, minHeight: 620)
                .preferredColorScheme(.dark)
                .onAppear { boot() }
                .onReceive(NotificationCenter.default.publisher(for: NSApplication.willTerminateNotification)) { _ in ledger.shutdown() }
        }
        .windowStyle(.hiddenTitleBar)
        .defaultSize(width: 1400, height: 860)
        .commands {
            CommandGroup(after: .appInfo) {
                Button("Check for Updates…") { Task { await UpdateChecker.check() } }
            }
            CommandGroup(after: .windowArrangement) {
                OpenRulesCommand()
            }
        }

        Window("Rules", id: "rules") {
            RulesWindow().environmentObject(ledger)
        }
        .defaultSize(width: 1000, height: 620)

        Settings {
            SettingsView().environmentObject(ledger)
        }
    }

    @MainActor private func boot() {
        ledger.start()
        if menuBar == nil {
            let m = MenuBarController(ledger: ledger)
            ledger.onTick = { [weak m] in m?.update() }
            menuBar = m
        }
        Task { await UpdateChecker.checkIfDue() }
        #if DEBUG
        // Lets screenshots and manual checks open a window at launch: RAT_OPEN=settings|rules
        switch ProcessInfo.processInfo.environment["RAT_OPEN"] {
        case "settings"?: DispatchQueue.main.asyncAfter(deadline: .now() + 2) { NSApp.activate(ignoringOtherApps: true); WindowOpener.open?("settings") }
        case "rules"?: DispatchQueue.main.asyncAfter(deadline: .now() + 2) { NSApp.activate(ignoringOtherApps: true); WindowOpener.open?("rules") }
        default: break
        }
        #endif
    }
}

/// ⌘⇧R opens the Rules window from the Window menu.
struct OpenRulesCommand: View {
    @Environment(\.openWindow) private var openWindow
    var body: some View {
        Button("Rules") { openWindow(id: "rules") }.keyboardShortcut("r", modifiers: [.command, .shift])
    }
}
