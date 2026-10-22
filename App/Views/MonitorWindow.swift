import SwiftUI

struct MonitorWindow: View {
    @EnvironmentObject var ledger: Ledger
    @State private var selection: String?
    @State private var showInspector = true
    @State private var showChart = true

    var body: some View {
        HStack(spacing: 0) {
            SidebarView(selection: $selection, showChart: $showChart, showInspector: $showInspector)
                .frame(width: 400)
            ZStack(alignment: .topTrailing) {
                MapPane(selection: selection)
                if showInspector {
                    InspectorView(selection: selection)
                        .frame(width: 330)
                        .background(.ultraThinMaterial)
                        .transition(.move(edge: .trailing))
                }
            }
        }
        .background(Color(nsColor: .windowBackgroundColor))
        .ignoresSafeArea()
        .animation(.easeInOut(duration: 0.2), value: showInspector)
    }
}
