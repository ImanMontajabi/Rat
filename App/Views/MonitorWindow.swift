import SwiftUI
import AppKit

struct MonitorWindow: View {
    @EnvironmentObject var ledger: Ledger
    @ObservedObject private var settings = AppSettings.shared
    @State private var selection: MonitorSelection?
    /// The place chosen on the map (a pin or a line): the inspector shows what goes there.
    @State private var place: MapPlace?
    @State private var showInspector = true
    @State private var showChart = true
    @State private var filter = MonitorFilter(hideLocal: AppSettings.shared.hideLocal)

    var body: some View {
        HStack(spacing: 0) {
            SidebarView(selection: $selection, showChart: $showChart, showInspector: $showInspector, filter: $filter)
                .frame(width: 400)
            MapPane(selection: selection, filter: filter, place: $place)
            if showInspector {
                InspectorView(selection: selection, filter: filter, place: $place,
                              showApp: { app in place = nil; selection = MonitorSelection(appID: app.id) })
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
        .onChange(of: filter.hideLocal) { _, on in settings.hideLocal = on }
        // Choosing a row in the list shows that row; choosing a place shows the inspector.
        .onChange(of: selection) { _, _ in place = nil }
        .onChange(of: place) { _, p in if p != nil { showInspector = true } }
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
