import SwiftUI
import AppKit
import RatFilterCore
import os

private let logger = Logger(subsystem: "com.imanmontajabi.Rat", category: "alerts")

struct ConnectionAlert: Identifiable, Equatable {
    let id = UUID()
    let appID: String
    let appName: String
    let host: String
    let address: String
    let port: Int
    let proto: String
    /// Who runs the server's network (`AS13335 Cloudflare, Inc.`), when the ASN database knows.
    var network: String? = nil
    /// "via VPN (…)" or "via System … Proxy (…)" when the connection takes that path.
    var route: String? = nil
    var key: String { "\(appID)|\(registrableDomain(host))" }
}

/// Queues unknown connections and shows them one at a time in a floating panel.
@MainActor
final class AlertCenter: ObservableObject {
    @Published private(set) var current: ConnectionAlert?
    private var queue: [ConnectionAlert] = []
    private var answeredOrQueued = Set<String>()
    private var panel: NSPanel?
    private unowned let rules: RulesModel
    private let onDecision: (ConnectionAlert, Verdict) -> Void
    var iconProvider: (String) -> NSImage = { _ in NSImage() }
    /// Set by the ledger: false once rules, a policy button or the mode have already answered this alert.
    var isStillPending: (ConnectionAlert) -> Bool = { _ in true }
    private var timeoutTask: Task<Void, Never>?

    init(rules: RulesModel, onDecision: @escaping (ConnectionAlert, Verdict) -> Void) {
        self.rules = rules
        self.onDecision = onDecision
    }

    var pendingCount: Int { queue.count + (current == nil ? 0 : 1) }

    func report(_ alert: ConnectionAlert) {
        guard answeredOrQueued.insert(alert.key).inserted else { return }
        queue.append(alert)
        logger.notice("alert queued for \(alert.appName, privacy: .public)")
        presentNext()
    }

    /// Drops queued alerts that no longer need an answer (e.g. the app got a process-wide Allow or Deny).
    func revalidate() {
        let before = queue.count
        queue.removeAll { a in
            let keep = isStillPending(a)
            if !keep { answeredOrQueued.remove(a.key) }
            return !keep
        }
        if let c = current, !isStillPending(c) {
            timeoutTask?.cancel()
            answeredOrQueued.remove(c.key)
            current = nil
            closePanel()
        }
        if before != queue.count || current == nil { presentNext() }
    }

    func answer(_ alert: ConnectionAlert, verdict: Verdict, scope: RulesModel.Scope, lifetime: Lifetime) {
        timeoutTask?.cancel()
        rules.addRule(from: alert, verdict: verdict, scope: scope, lifetime: lifetime)
        onDecision(alert, verdict)
        // A "once" answer should not silence the next connection from the same app.
        if lifetime == .once { answeredOrQueued.remove(alert.key) }
        current = nil
        closePanel()
        presentNext()
    }

    private func presentNext() {
        guard current == nil, !queue.isEmpty else { return }
        // Skip anything answered while it waited in the queue.
        while let next = queue.first, !isStillPending(next) { answeredOrQueued.remove(next.key); queue.removeFirst() }
        guard !queue.isEmpty else { return }
        current = queue.removeFirst()
        showPanel()
        startTimeout()
    }

    /// Settings > Alert: confirm automatically after N seconds.
    private func startTimeout() {
        let secs = AppSettings.shared.alertTimeout
        guard secs > 0, let alert = current else { return }
        timeoutTask = Task { [weak self] in
            try? await Task.sleep(for: .seconds(secs))
            guard !Task.isCancelled, let self, self.current == alert else { return }
            let allow = AppSettings.shared.alertTimeoutAllows
            if AppSettings.shared.notifyAlertTimeout {
                Notifier.post(title: allow ? "Connection allowed after timeout" : "Connection denied after timeout", body: "\(alert.appName) → \(alert.host)")
            }
            self.answer(alert, verdict: allow ? .allow : .deny, scope: .any, lifetime: .once)
        }
    }

    private func showPanel() {
        guard let alert = current else { return }
        let view = AlertView(alert: alert, icon: iconProvider(alert.appID), remaining: queue.count) { [weak self] verdict, scope, lifetime in
            self?.answer(alert, verdict: verdict, scope: scope, lifetime: lifetime)
        }
        let host = NSHostingView(rootView: view.preferredColorScheme(.dark))
        host.setFrameSize(host.fittingSize)
        let p = NSPanel(contentRect: NSRect(origin: .zero, size: host.fittingSize),
                        styleMask: [.titled, .fullSizeContentView, .nonactivatingPanel, .hudWindow, .utilityWindow],
                        backing: .buffered, defer: false)
        p.titleVisibility = .hidden
        p.titlebarAppearsTransparent = true
        p.isFloatingPanel = true
        p.level = .floating
        p.hidesOnDeactivate = false
        p.isMovableByWindowBackground = true
        p.collectionBehavior = [.canJoinAllSpaces, .fullScreenAuxiliary]
        p.contentView = host
        if let screen = NSScreen.main {
            p.setFrameOrigin(NSPoint(x: screen.visibleFrame.maxX - p.frame.width - 20, y: screen.visibleFrame.maxY - p.frame.height - 20))
        }
        p.orderFrontRegardless()
        panel = p
    }

    private func closePanel() { panel?.orderOut(nil); panel = nil }
}

struct AlertView: View {
    let alert: ConnectionAlert
    let icon: NSImage
    let remaining: Int
    let decide: (Verdict, RulesModel.Scope, Lifetime) -> Void

    @ObservedObject private var settings = AppSettings.shared
    // One click should cover the app, not just one of its many server addresses.
    @State private var scope: RulesModel.Scope = .any
    @State private var lifetime: Lifetime = .forever

    private var target: String {
        alert.host == alert.address ? alert.address : alert.host
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(spacing: 12) {
                Image(nsImage: icon).resizable().frame(width: 44, height: 44)
                VStack(alignment: .leading, spacing: 2) {
                    Text(alert.appName).font(.title3.weight(.semibold))
                    Text("wants to connect to").font(.callout).foregroundStyle(.secondary)
                }
                Spacer()
                if remaining > 0 { Text("+\(remaining)").font(.caption).padding(6).background(.white.opacity(0.12), in: Capsule()) }
            }
            VStack(alignment: .leading, spacing: 2) {
                Text(target).font(.headline).textSelection(.enabled)
                Text("\(alert.proto) port \(alert.port)" + (usualService(proto: alert.proto, port: alert.port).map { " (usually \($0))" } ?? "") + (alert.address.isEmpty ? "" : " · \(alert.address)"))
                    .font(.caption).foregroundStyle(.secondary)
                if let route = alert.route {
                    Label(route, systemImage: route.hasPrefix("via VPN") ? "lock.shield" : "arrow.triangle.branch").font(.caption).foregroundStyle(.secondary)
                }
                if let network = alert.network {
                    Text("Network: \(network)").font(.caption).foregroundStyle(.secondary).help("The organization that runs the server's network (often a cloud or hosting provider), not necessarily who runs the service.")
                }
            }
            Divider()
            Picker("Applies to", selection: $scope) { ForEach(RulesModel.Scope.allCases) { Text($0.rawValue).tag($0) } }
            Picker("Keep rule", selection: $lifetime) {
                Text("Once").tag(Lifetime.once); Text("Until Quit").tag(Lifetime.untilQuit); Text("Forever").tag(Lifetime.forever)
            }.pickerStyle(.segmented)
            Text("The connection has already started. Deny cuts this app’s connection off; other apps can still reach the server.")
                .font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            HStack {
                Button { decide(.deny, scope, lifetime) } label: { Label("Deny", systemImage: "xmark").frame(maxWidth: .infinity) }
                    .modifier(OptionalShortcut(key: .cancelAction, enabled: settings.confirmWithReturn)).tint(.red)
                Button { decide(.allow, scope, lifetime) } label: { Label("Allow", systemImage: "checkmark").frame(maxWidth: .infinity) }
                    .modifier(OptionalShortcut(key: .defaultAction, enabled: settings.confirmWithReturn)).buttonStyle(.borderedProminent).tint(.green)
            }
            .controlSize(.large)
        }
        .padding(18)
        .frame(width: 380)
        .background(.regularMaterial)
    }
}

/// "Confirm with Return and Escape" can be turned off to avoid accidental answers.
struct OptionalShortcut: ViewModifier {
    let key: KeyboardShortcut
    let enabled: Bool
    @ViewBuilder func body(content: Content) -> some View {
        if enabled { content.keyboardShortcut(key) } else { content }
    }
}
