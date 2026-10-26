import SwiftUI

/// The tags of a connection that does not go straight to its server: `VPN · Windscribe · utun3` (teal),
/// `Proxy · ssh` (orange) for a local or system proxy, including destinations unmasked behind a local proxy.
struct RouteBadges: View {
    let remote: RemoteHost
    /// Narrow rows leave out the tunnel interface.
    var compact = false

    var body: some View {
        HStack(spacing: 4) {
            if let route = remote.route { badge(compact ? route.shortBadge : route.badge, symbol: route.isVPN ? "lock.shield" : "arrow.triangle.branch", color: route.isVPN ? .teal : .orange, help: route.help) }
            if let via = remote.via, !(remote.route?.isProxy ?? false) {
                badge("Proxy · \(via.process)", symbol: "arrow.triangle.branch", color: .orange, help: "\(via.label), \(via.kind)")
            }
        }
    }

    private func badge(_ text: String, symbol: String, color: Color, help: String) -> some View {
        Label(text, systemImage: symbol)
            .labelStyle(.titleAndIcon).font(.system(size: 9, weight: .semibold)).lineLimit(1)
            .padding(.horizontal, 5).padding(.vertical, 1)
            .foregroundStyle(color)
            .background(color.opacity(0.15), in: Capsule())
            .fixedSize()
            .help(help)
            .accessibilityIdentifier("badge-\(text)")
    }
}

struct Pill: View {
    enum Kind { case up, down }
    let kind: Kind
    let text: String
    var label: String? = nil
    var body: some View {
        HStack(spacing: 6) {
            Image(systemName: kind == .up ? "arrow.up" : "arrow.down").fontWeight(.bold)
            if let label { Text(label).font(.callout) }
            Spacer(minLength: 0)
            Text(text).font(.title3.weight(.semibold)).monospacedDigit()
        }
        .padding(.horizontal, 12).padding(.vertical, 7)
        .foregroundStyle(.white)
        .background(kind == .up ? Color(red: 0.55, green: 0.25, blue: 0.75).opacity(0.75) : Color(red: 0.15, green: 0.40, blue: 0.85).opacity(0.75),
                    in: RoundedRectangle(cornerRadius: 12))
    }
}

/// Deny / allow button pair shown on each process row.
struct PolicyToggle: View {
    let policy: Policy?
    let set: (Policy?) -> Void

    var body: some View {
        HStack(spacing: 2) {
            cell("xmark", active: policy == .deny, tint: .red) { set(policy == .deny ? nil : .deny) }
            cell("checkmark", active: policy == .allow, tint: .green) { set(policy == .allow ? nil : .allow) }
        }
    }

    private func cell(_ symbol: String, active: Bool, tint: Color, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            Image(systemName: symbol).font(.system(size: 11, weight: .bold))
                .frame(width: 22, height: 20)
                .foregroundStyle(active ? .white : (policy == nil ? .white : .secondary))
                .background(active ? tint : (policy == nil ? Color.blue : Color.gray.opacity(0.35)), in: RoundedRectangle(cornerRadius: 5))
        }
        .buttonStyle(.plain)
    }
}

/// Tiny stacked bar activity indicator.
struct Sparkline: View {
    let rates: [(rx: Double, tx: Double)]
    var body: some View {
        let peak = max(rates.map { $0.rx + $0.tx }.max() ?? 1, 1)
        HStack(alignment: .bottom, spacing: 1.5) {
            ForEach(0..<14, id: \.self) { i in
                let idx = i - (14 - rates.count)
                let r = idx >= 0 ? rates[idx] : (rx: 0, tx: 0)
                VStack(spacing: 0) {
                    Rectangle().fill(.purple).frame(height: 16 * r.tx / peak)
                    Rectangle().fill(.blue).frame(height: 16 * r.rx / peak)
                    if r.rx + r.tx == 0 { Rectangle().fill(.white.opacity(0.12)).frame(height: 16) }
                }
                .frame(width: 3, height: 16, alignment: .bottom)
            }
        }
        .frame(height: 16)
    }
}

struct SectionHeader: View {
    let title: String
    @Binding var open: Bool
    var body: some View {
        Button { withAnimation(.easeInOut(duration: 0.15)) { open.toggle() } } label: {
            HStack {
                Image(systemName: open ? "chevron.down" : "chevron.right").font(.caption2)
                Text(title).font(.callout).foregroundStyle(.secondary)
                Spacer()
            }
            .padding(.horizontal, 10).padding(.vertical, 5)
            .background(.white.opacity(0.07), in: RoundedRectangle(cornerRadius: 6))
        }
        .buttonStyle(.plain)
    }
}
