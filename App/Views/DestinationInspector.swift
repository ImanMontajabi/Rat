import SwiftUI

/// The inspector for a place chosen on the map: what goes there, by app and by connection, with the connections'
/// ✗/✓. Its scope is the map's: the listed apps, the row selected in the list, and the filter.
struct DestinationInspector: View {
    @EnvironmentObject var ledger: Ledger
    @ObservedObject private var settings = AppSettings.shared
    let place: MapPlace
    let summary: DestinationSummary
    /// Shows an app in the list and the inspector (and lets go of the place).
    let showApp: (AppEntry) -> Void
    /// Lets go of the place (the close button, Escape).
    let close: () -> Void
    @State private var appsOpen = true
    @State private var connectionsOpen = true

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(alignment: .top, spacing: 10) {
                Text(place.point.flag.isEmpty ? "📍" : place.point.flag).font(.system(size: 34))
                VStack(alignment: .leading, spacing: 0) {
                    Text(place.point.city.isEmpty ? place.point.country : place.point.city).font(.title2.weight(.bold)).lineLimit(2)
                    if !place.point.city.isEmpty, !place.point.country.isEmpty { Text(place.point.country).font(.callout).foregroundStyle(.secondary) }
                }
                .accessibilityElement(children: .combine)
                .accessibilityIdentifier("destination-title")
                Spacer(minLength: 4)
                Button(action: close) { Image(systemName: "xmark.circle.fill").font(.title3).foregroundStyle(.secondary) }
                    .buttonStyle(.plain)
                    .keyboardShortcut(.cancelAction)
                    .help("Back to the summary (Esc)")
                    .accessibilityLabel("Close the place")
                    .accessibilityIdentifier("destination-clear")
            }
            Text(Self.counts(connections: summary.connections.count, apps: summary.apps.count))
                .font(.callout).foregroundStyle(.secondary)
                .accessibilityIdentifier("destination-counts")
            HStack(spacing: 8) {
                Pill(kind: .up, text: formatBytes(summary.bytesOut))
                Pill(kind: .down, text: formatBytes(summary.bytesIn))
            }
            .help("Sent and received on the open connections to this place")
            Text("Now ↑ \(settings.formatRate(summary.rateOut))  ↓ \(settings.formatRate(summary.rateIn))")
                .font(.callout.monospacedDigit()).foregroundStyle(.secondary)
                .accessibilityIdentifier("destination-rate")

            SectionHeader(title: "Apps", open: $appsOpen)
            if appsOpen {
                if summary.apps.isEmpty { Text("No app connects here now.").foregroundStyle(.secondary).padding(.leading, 6) }
                ForEach(summary.apps) { a in appRow(a) }
            }
            SectionHeader(title: "Connections", open: $connectionsOpen)
            if connectionsOpen {
                if summary.connections.isEmpty { Text("No open connections.").foregroundStyle(.secondary).padding(.leading, 6) }
                ForEach(summary.connections.prefix(100)) { c in connectionRow(c) }
                if summary.connections.count > 100 {
                    Text("and \(summary.connections.count - 100) more").font(.caption).foregroundStyle(.secondary).padding(.leading, 6)
                }
            }
        }
    }

    /// "3 connections from 2 apps".
    static func counts(connections: Int, apps: Int) -> String {
        "\(connections) connection\(connections == 1 ? "" : "s") from \(apps) app\(apps == 1 ? "" : "s")"
    }

    private func appRow(_ a: DestinationApp) -> some View {
        Button { showApp(a.app) } label: {
            HStack(spacing: 8) {
                Image(nsImage: a.app.identity.icon).resizable().frame(width: 22, height: 22)
                VStack(alignment: .leading, spacing: 0) {
                    Text(a.app.identity.name).font(.system(size: 13, weight: .medium)).lineLimit(1)
                    Text("\(a.connections) connection\(a.connections == 1 ? "" : "s") · \(formatBytes(a.bytesIn + a.bytesOut))")
                        .font(.caption).foregroundStyle(.secondary).lineLimit(1)
                }
                Spacer(minLength: 4)
                if a.rateIn + a.rateOut > 0 {
                    Text("↓ \(settings.formatRate(a.rateIn))").font(.caption.monospacedDigit()).foregroundStyle(.secondary).lineLimit(1).fixedSize()
                }
                Image(systemName: "chevron.right").font(.caption2).foregroundStyle(.tertiary)
            }
            .padding(.vertical, 3).padding(.horizontal, 6)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .help("Show \(a.app.identity.name) in the list")
        .accessibilityElement(children: .combine)
        .accessibilityAddTraits(.isButton)
        .accessibilityIdentifier("destination-app-\(a.app.identity.name)")
    }

    private func connectionRow(_ c: DestinationConnection) -> some View {
        let r = c.remote
        return HStack(alignment: .center, spacing: 6) {
            Image(nsImage: c.app.identity.icon).resizable().frame(width: 16, height: 16).help(c.app.identity.name)
            VStack(alignment: .leading, spacing: 1) {
                HStack(spacing: 4) {
                    Text(r.host).font(.caption.weight(.medium)).lineLimit(1).truncationMode(.middle)
                    ForEach(RouteBadges.items(r, compact: true), id: \.self) { RouteBadge(item: $0, symbolOnly: true) }
                }
                Text(Self.detail(c))
                    .font(.caption2).foregroundStyle(.secondary).lineLimit(1).truncationMode(.middle)
                if r.rateIn + r.rateOut > 0 {
                    Text("↑ \(settings.formatRate(r.rateOut))  ↓ \(settings.formatRate(r.rateIn))").font(.caption2.monospacedDigit()).foregroundStyle(.secondary)
                }
            }
            .help("\(c.app.identity.name)\(r.process.map { $0 == c.app.mainProcess ? "" : " via \($0)" } ?? "") · \(r.host)\(r.address.isEmpty || r.address == r.host ? "" : " (\(r.address))")")
            .accessibilityElement(children: .combine)
            .accessibilityIdentifier("destination-remote-\(r.host)")
            Spacer(minLength: 4)
            HStack(spacing: 0) {
                RowPolicy(app: c.app, target: c.app.ruleTarget(process: c.app.mainProcess, remote: r), service: r.process, subject: "this connection")
            }
            .accessibilityElement(children: .contain)
            .accessibilityIdentifier("destination-policy-\(r.host)")
        }
        .padding(.vertical, 2).padding(.leading, 6)
    }

    /// "Google Chrome · TCP 443 · https · 1.2 MB", with "via proxy server" for a connection that only passes the place.
    static func detail(_ c: DestinationConnection) -> String {
        let r = c.remote
        var parts = [c.app.identity.name, "\(r.proto) \(r.port)\(serviceSuffix(proto: r.proto, port: r.port))"]
        if r.bytesIn + r.bytesOut > 0 { parts.append(formatBytes(r.bytesIn + r.bytesOut)) }
        if c.throughProxyServer, let to = r.geo?.city, !to.isEmpty { parts.append("via proxy to \(to)") }
        return parts.joined(separator: " · ")
    }
}
