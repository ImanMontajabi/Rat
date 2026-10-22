import SwiftUI

@main
struct RatApp: App {
    @StateObject private var ledger = Ledger()

    var body: some Scene {
        WindowGroup("Rat") {
            MonitorWindow()
                .environmentObject(ledger)
                .frame(minWidth: 1000, minHeight: 620)
                .preferredColorScheme(.dark)
                .onAppear { ledger.start() }
                .onReceive(NotificationCenter.default.publisher(for: NSApplication.willTerminateNotification)) { _ in ledger.save() }
        }
        .windowStyle(.hiddenTitleBar)
        .defaultSize(width: 1400, height: 860)
        .commands {
            CommandGroup(after: .appInfo) {
                Button("Check for Updates…") { Task { await UpdateChecker.check() } }
            }
        }
    }
}
