import SwiftUI
import RatMonitor
import os

private let logger = Logger(subsystem: "com.imanmontajabi.Rat", category: "ui")

@MainActor
final class ConnectionsModel: ObservableObject {
    @Published var rows: [ObservedConnection] = []
    private var task: Task<Void, Never>?

    func start() {
        guard task == nil else { return }
        logger.notice("monitor started")
        task = Task.detached(priority: .utility) { [weak self] in
            while !Task.isCancelled {
                let sample = ConnectionSampler.sample().filter(\.isOutbound)
                await MainActor.run { self?.rows = sample.sorted { ($0.processName, $0.remoteAddress) < ($1.processName, $1.remoteAddress) } }
                try? await Task.sleep(for: .seconds(2))
            }
        }
    }
}

struct ConnectionsView: View {
    @StateObject private var model = ConnectionsModel()
    @State private var search = ""

    private var filtered: [ObservedConnection] {
        search.isEmpty ? model.rows : model.rows.filter {
            $0.processName.localizedCaseInsensitiveContains(search) || $0.remoteAddress.contains(search)
        }
    }

    var body: some View {
        Table(filtered) {
            TableColumn("Process", value: \.processName)
            TableColumn("PID") { Text(String($0.pid)).monospacedDigit() }.width(60)
            TableColumn("Remote") { Text($0.remoteAddress) }
            TableColumn("Port") { Text(String($0.remotePort)).monospacedDigit() }.width(60)
            TableColumn("Proto") { Text($0.proto.rawValue.uppercased()) }.width(60)
            TableColumn("State") { Text($0.tcpState ?? "") }
        }
        .searchable(text: $search)
        .navigationTitle("Rat: \(filtered.count) connections")
        .onAppear { model.start() }
    }
}

extension ObservedConnection: Identifiable {
    public var id: String { "\(pid)|\(proto)|\(localPort)|\(remoteAddress)|\(remotePort)" }
}
