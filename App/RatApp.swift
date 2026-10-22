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
        Window("Rat", id: "monitor") {
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
        }

        Window("Rules & Profiles", id: "rules") {
            RulesWindow().environmentObject(ledger)
        }
        .defaultSize(width: 900, height: 600)
    }

    @MainActor private func boot() {
        ledger.start()
        if menuBar == nil {
            let m = MenuBarController(ledger: ledger)
            ledger.onTick = { [weak m] in m?.update() }
            menuBar = m
        }
    }
}
