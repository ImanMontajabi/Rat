import SwiftUI

@main
struct RatApp: App {
    var body: some Scene {
        WindowGroup("Rat") {
            ConnectionsView()
                .frame(minWidth: 760, minHeight: 420)
        }
    }
}
