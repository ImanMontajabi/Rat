import SwiftUI

/// The tags of a connection that does not go straight to its server: `VPN · Windscribe · utun3` (teal),
/// `Proxy · ssh` (orange) for a local or system proxy, including destinations unmasked behind a local proxy, and
/// `VPN server · Windscribe` (grey) for the VPN client's own connection that carries the tunnel. After them, in
/// blue, the direction: `↓ Incoming` for a connection a peer started, `↓ stream` for a long-lived download.
struct RouteBadges: View {
    let remote: RemoteHost
    /// Narrow rows leave out the tunnel interface.
    var compact = false

    struct Item: Hashable {
        var text: String
        var symbol: String
        var vpn: Bool
        var carrier = false
        var direction = false
        var help: String
        var color: Color { direction ? .ratAccent : carrier ? .secondary : vpn ? .ratVPN : .ratProxy }
    }

    /// `directions`: also the direction tags (a connection's own row and the inspector; not an app's summary).
    static func items(_ r: RemoteHost, compact: Bool, directions: Bool = true) -> [Item] {
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
        guard directions else { return out }
        if r.incoming {
            out.append(Item(text: "Incoming", symbol: "arrow.down", vpn: false, direction: true,
                            help: "\(r.address) started this connection to port \(r.port) of this Mac, where \(r.process ?? "a program") listens. Rules decide what this Mac connects to, so this row has no ✗/✓."))
        } else if r.stream {
            out.append(Item(text: "stream", symbol: "arrow.down", vpn: false, direction: true,
                            help: "Open for a while and mostly receiving: a download, a server push (such as Server-Sent Events) or a media stream. Rat sees how many bytes pass, not what they carry."))
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
    /// Only the symbols, for a row that chooses its own fallbacks (a process row keeps its pid before its tags' text).
    var symbolsOnly = false

    static func items(_ remotes: [RemoteHost]) -> [RouteBadges.Item] {
        var seen = Set<String>(), out: [RouteBadges.Item] = []
        for r in remotes { for i in RouteBadges.items(r, compact: true, directions: false) where seen.insert(i.text).inserted { out.append(i) } }
        return out.sorted { ($0.vpn ? 0 : $0.carrier ? 2 : 1, $0.text) < ($1.vpn ? 0 : $1.carrier ? 2 : 1, $1.text) }
    }

    var body: some View {
        let items = Self.items(remotes)
        if !items.isEmpty {
            // The row's name keeps its room: with less space the tags step down to the first one and a count,
            // then to their symbols (each still names itself in its tooltip).
            if symbolsOnly {
                symbols(items)
            } else {
                ViewThatFits(in: .horizontal) {
                    badges(items, shown: 2)
                    badges(items, shown: 1)
                    symbols(items)
                }
            }
        }
    }

    private func symbols(_ items: [RouteBadges.Item]) -> some View {
        HStack(spacing: 3) { ForEach(items, id: \.self) { RouteBadge(item: $0, symbolOnly: true) } }
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
    private var quiet: Bool { item.vpn && !item.carrier && !item.direction }

    var body: some View {
        Group {
            if symbolOnly { Image(systemName: item.symbol).accessibilityLabel(item.text) } else { Label(item.text, systemImage: item.symbol) }
        }
            // A tunnel's tag repeats on most rows while a VPN carries everything: smaller and quieter, so the names
            // lead. Proxies, the tunnel's own carrier (`VPN server · …`) and directions keep the full tag.
            .font(.system(size: quiet ? 8.5 : 9, weight: .semibold)).lineLimit(1)
            .padding(.horizontal, quiet ? 4 : 5).padding(.vertical, quiet ? 0.5 : 1)
            .foregroundStyle(item.color.opacity(quiet ? 0.72 : 1))
            .background(item.color.opacity(quiet ? 0.07 : 0.15), in: Capsule())
            .fixedSize()
            .help(item.help)
            .accessibilityIdentifier("badge-\(item.text)")
    }
}

/// A traffic total: the arrow in a small round badge of the traffic colour, then the amount (`↑ 26,5 MB`), the same
/// in the list's footer and every inspector.
struct Pill: View {
    enum Kind { case up, down }
    let kind: Kind
    let text: String
    private var tint: Color { kind == .up ? .ratSent : .ratReceived }
    var body: some View {
        HStack(spacing: 8) {
            Image(systemName: kind == .up ? "arrow.up" : "arrow.down").font(.system(size: 10, weight: .bold))
                .foregroundStyle(Color.ratOnAccent)
                .frame(width: 18, height: 18).background(tint, in: Circle())
            Spacer(minLength: 0)
            Text(text).font(.title3.weight(.semibold)).monospacedDigit().foregroundStyle(tint)
        }
        .padding(.leading, 7).padding(.trailing, 12).padding(.vertical, 6)
        // Matte: the traffic colour on a soft fill of itself (OpenWarp's `Tint.soft`), peach out, blue in.
        .background(tint.opacity(0.14), in: RoundedRectangle(cornerRadius: Radius.md))
        .accessibilityElement(children: .combine)
        .accessibilityLabel("\(kind == .up ? "Sent" : "Received") \(text)")
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
    @State private var hovered: Policy?

    /// One pill, `[ ✗ | ✓ ]`: quiet until it matters. A choice fills its half with its pastel (dark glyph); one
    /// followed from a wider row a soft tint of it; otherwise both glyphs are faint on a faint fill, and the half
    /// under the pointer lights up in its colour. Each half is its own button (`policy-deny`, `policy-allow`).
    var body: some View {
        HStack(spacing: 0) {
            cell("xmark", choice: .deny, tint: .ratDanger)
                .accessibilityLabel("Deny").accessibilityIdentifier("policy-deny")
            cell("checkmark", choice: .allow, tint: .ratSuccess)
                .accessibilityLabel("Allow").accessibilityIdentifier("policy-allow")
        }
        .background(alignment: .center) {
            Capsule().fill(Color.ratRaised.opacity(hovered == nil ? (compact ? 0.35 : 0.5) : 0.9))
                .frame(width: size.width * 2, height: size.height)
                .overlay { Rectangle().fill(Color.white.opacity(0.1)).frame(width: 1, height: size.height * 0.5) }
        }
        .animation(Motion.quick, value: hovered)
    }

    private var size: CGSize { compact ? CGSize(width: 20, height: 16) : CGSize(width: 24, height: 20) }

    private func cell(_ symbol: String, choice: Policy, tint: Color) -> some View {
        let active = policy == choice
        let follows = policy == nil && inherited == choice
        let hover = hovered == choice
        let fill: Color = active ? tint : follows ? tint.opacity(0.2) : .clear
        let glyph: Color = active ? .ratOnAccent : follows || hover ? tint : Color.white.opacity(hovered != nil ? 0.45 : 0.22)
        let half = UnevenRoundedRectangle(topLeadingRadius: choice == .deny ? size.height / 2 : 0, bottomLeadingRadius: choice == .deny ? size.height / 2 : 0,
                                          bottomTrailingRadius: choice == .allow ? size.height / 2 : 0, topTrailingRadius: choice == .allow ? size.height / 2 : 0)
        let verb = choice == .deny ? "Deny" : "Allow"
        return Button { set(active ? nil : choice) } label: {
            Image(systemName: symbol).font(.system(size: compact ? 8.5 : 10.5, weight: .bold))
                .frame(width: size.width, height: size.height)
                .foregroundStyle(glyph)
                .background(fill, in: half)
                // The small pill is drawn small but hit like the app row's: a click just above or below it counts.
                .frame(height: 20)
                .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .onHover { inside in hovered = inside ? choice : (hovered == choice ? nil : hovered) }
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
                    Rectangle().fill(Color.ratSent).frame(height: 16 * r.tx / peak)
                    Rectangle().fill(Color.ratReceived).frame(height: 16 * r.rx / peak)
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
