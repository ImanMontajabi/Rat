import SwiftUI

/// The tags of a connection that does not go straight to its server: `VPN · Windscribe · utun3` (teal),
/// `Proxy · ssh` (orange) for a local or system proxy, including destinations unmasked behind a local proxy, and
/// `VPN server · Windscribe` (grey) for the VPN client's own connection that carries the tunnel.
struct RouteBadges: View {
    let remote: RemoteHost
    /// Narrow rows leave out the tunnel interface.
    var compact = false

    struct Item: Hashable {
        var text: String
        var symbol: String
        var vpn: Bool
        var carrier = false
        var help: String
        var color: Color { carrier ? .secondary : vpn ? .teal : .orange }
    }

    static func items(_ r: RemoteHost, compact: Bool) -> [Item] {
        var out: [Item] = []
        if let route = r.route {
            if case .vpnServer = route {
                out.append(Item(text: route.badge, symbol: "server.rack", vpn: false, carrier: true, help: route.help))
            } else {
                out.append(Item(text: compact ? route.shortBadge : route.badge, symbol: route.isVPN ? "lock.shield" : "arrow.triangle.branch", vpn: route.isVPN, help: route.help))
            }
        }
        if let via = r.via, !(r.route?.isProxy ?? false) {
            out.append(Item(text: via.badge, symbol: "arrow.triangle.branch", vpn: false, help: "\(via.label), \(via.kind)"))
        }
        return out
    }

    var body: some View {
        HStack(spacing: 4) { ForEach(Self.items(remote, compact: compact), id: \.self) { RouteBadge(item: $0) } }
    }
}

/// The routes an app's or a process's connections take, on its row: each distinct tag once, VPNs first, at most
/// two and a count of the rest ("VPN · Windscribe", "Proxy · ssh", "+1").
struct RouteSummaryBadges: View {
    let remotes: [RemoteHost]

    static func items(_ remotes: [RemoteHost]) -> [RouteBadges.Item] {
        var seen = Set<String>(), out: [RouteBadges.Item] = []
        for r in remotes { for i in RouteBadges.items(r, compact: true) where seen.insert(i.text).inserted { out.append(i) } }
        return out.sorted { ($0.vpn ? 0 : $0.carrier ? 2 : 1, $0.text) < ($1.vpn ? 0 : $1.carrier ? 2 : 1, $1.text) }
    }

    var body: some View {
        let items = Self.items(remotes)
        if !items.isEmpty {
            // The row's name keeps its room: with less space the tags step down to the first one and a count,
            // then to their symbols (each still names itself in its tooltip).
            ViewThatFits(in: .horizontal) {
                badges(items, shown: 2)
                badges(items, shown: 1)
                HStack(spacing: 3) { ForEach(items, id: \.self) { RouteBadge(item: $0, symbolOnly: true) } }
            }
        }
    }

    private func badges(_ items: [RouteBadges.Item], shown: Int) -> some View {
        HStack(spacing: 3) {
            ForEach(items.prefix(shown), id: \.self) { RouteBadge(item: $0) }
            if items.count > shown {
                Text("+\(items.count - shown)").font(.system(size: 9, weight: .semibold)).foregroundStyle(.secondary)
                    .help(items.dropFirst(shown).map(\.text).joined(separator: ", "))
            }
        }
    }
}

struct RouteBadge: View {
    let item: RouteBadges.Item
    var symbolOnly = false

    var body: some View {
        Group {
            if symbolOnly { Image(systemName: item.symbol).accessibilityLabel(item.text) } else { Label(item.text, systemImage: item.symbol) }
        }
            .font(.system(size: 9, weight: .semibold)).lineLimit(1)
            .padding(.horizontal, 5).padding(.vertical, 1)
            .foregroundStyle(item.color)
            .background(item.color.opacity(0.15), in: Capsule())
            .fixedSize()
            .help(item.help)
            .accessibilityIdentifier("badge-\(item.text)")
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

/// Deny / allow button pair shown on each row of the process list. A process or connection row without a choice of
/// its own shows the one it follows (`inherited`, from its process or app) muted; clicking sets its own.
struct PolicyToggle: View {
    let policy: Policy?
    var inherited: Policy? = nil
    /// The smaller pair of the process and connection rows.
    var compact = false
    /// "this process", "this connection": for the help text.
    var subject = "this app"
    let set: (Policy?) -> Void

    var body: some View {
        HStack(spacing: compact ? 0 : 2) {
            cell("xmark", choice: .deny, tint: .red)
                .accessibilityLabel("Deny").accessibilityIdentifier("policy-deny")
            cell("checkmark", choice: .allow, tint: .green)
                .accessibilityLabel("Allow").accessibilityIdentifier("policy-allow")
        }
    }

    private func cell(_ symbol: String, choice: Policy, tint: Color) -> some View {
        let active = policy == choice
        let follows = policy == nil && inherited == choice
        let undecided = policy == nil && inherited == nil
        let fill: Color = active ? tint : follows ? tint.opacity(0.35) : undecided && !compact ? .blue : .gray.opacity(compact ? 0.2 : 0.35)
        let verb = choice == .deny ? "Deny" : "Allow"
        return Button { set(active ? nil : choice) } label: {
            Image(systemName: symbol).font(.system(size: compact ? 9 : 11, weight: .bold))
                .frame(width: compact ? 18 : 22, height: compact ? 16 : 20)
                .foregroundStyle(active || follows || (undecided && !compact) ? .white : .secondary)
                .background(fill, in: RoundedRectangle(cornerRadius: compact ? 4 : 5))
                // The small pair is drawn small but hit like the app row's: a click just beside it still counts.
                .frame(width: 22, height: 20)
                .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .help(active ? "\(verb) \(subject) (click to clear)" : follows ? "\(choice == .deny ? "Denied" : "Allowed") by the wider row; click to \(verb.lowercased()) \(subject) itself" : "\(verb) \(subject)")
        .accessibilityValue(active ? "on" : follows ? "inherited" : "off")
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
