import SwiftUI
import AppKit

struct MonitorWindow: View {
    @EnvironmentObject var ledger: Ledger
    @ObservedObject private var settings = AppSettings.shared
    @State private var selection: String?
    @State private var showInspector = true
    @State private var showChart = true

    var body: some View {
        HStack(spacing: 0) {
            SidebarView(selection: $selection, showChart: $showChart, showInspector: $showInspector)
                .frame(width: 400)
            MapPane(selection: selection)
            if showInspector {
                InspectorView(selection: selection)
                    .frame(width: 330)
                    .background(.ultraThinMaterial)
                    .transition(.move(edge: .trailing))
            }
        }
        .background(Color(nsColor: .windowBackgroundColor))
        .ignoresSafeArea()
        .animation(.easeInOut(duration: 0.2), value: showInspector)
        .modifier(OpenWindowBridge())
        .background(WindowLevelSetter(floating: settings.floatOnTop))
    }
}

/// Applies "Float on Top" to the window that hosts this view.
struct WindowLevelSetter: NSViewRepresentable {
    let floating: Bool
    func makeNSView(context: Context) -> NSView { NSView() }
    func updateNSView(_ view: NSView, context: Context) {
        DispatchQueue.main.async { view.window?.level = floating ? .floating : .normal }
    }
}
