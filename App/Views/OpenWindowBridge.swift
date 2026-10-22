import SwiftUI

/// Lets the AppKit status item open SwiftUI windows and the Settings scene.
struct OpenWindowBridge: ViewModifier {
    @Environment(\.openWindow) private var openWindow
    @Environment(\.openSettings) private var openSettings
    func body(content: Content) -> some View {
        content.onAppear {
            WindowOpener.open = { id in
                if id == "settings" { openSettings() } else { openWindow(id: id) }
            }
        }
    }
}
