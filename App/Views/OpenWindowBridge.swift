import SwiftUI

/// Lets the AppKit status item open SwiftUI windows.
struct OpenWindowBridge: ViewModifier {
    @Environment(\.openWindow) private var openWindow
    func body(content: Content) -> some View {
        content.onAppear { WindowOpener.open = { id in openWindow(id: id) } }
    }
}
