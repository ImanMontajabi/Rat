import SwiftUI
import AppKit
import RatFilterCore

/// The panel under Rat's menu bar icon (Little Snitch calls its own Control Center): whether denying is enforced,
/// the traffic now and over the last minutes, how the Internet leaves the Mac, the apps moving data, the mode and
/// profile, and the windows. Everything comes from the ledger's last pass; the panel polls nothing of its own and
/// exists only while it is open (`MenuBarController` drops it on close).
struct ControlCenterPanel: View {
    @EnvironmentObject var ledger: Ledger
    @ObservedObject var rules: RulesModel
    @ObservedObject var enforcer: Enforcer
    @ObservedObject var alerts: AlertCenter
    @ObservedObject private var settings = AppSettings.shared
    /// Opens a window ("monitor", "rules", "settings") and closes the panel.
    var open: (String) -> Void = { _ in }
    var quit: () -> Void = {}
    /// Fixed state for snapshot tests, which must not depend on this Mac's helper or VPN.
    var fixedProtection: ControlCenter.Protection? = nil
    var fixedRoute: ControlCenter.Route? = nil

    static let width: CGFloat = 340

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            status.padding(.horizontal, Space.md).padding(.top, Space.md).padding(.bottom, Space.sm)
            divider
            traffic.padding(.horizontal, Space.md).padding(.vertical, Space.sm)
            divider
            routeRow.padding(.horizontal, Space.md).padding(.vertical, 10)
            divider
            activity.padding(.horizontal, Space.xs).padding(.vertical, Space.xs)
            divider
            controls.padding(.horizontal, Space.md).padding(.vertical, Space.sm)
            if let p = ControlCenter.pending(alerts: alerts.pendingCount, unapproved: rules.unapprovedCount) {
                divider
                Button { open("rules") } label: {
                    Label(p, systemImage: "exclamationmark.bubble").font(Typo.caption).foregroundStyle(Color.ratWarning)
                        .frame(maxWidth: .infinity, alignment: .leading).contentShape(Rectangle())
                }
                .buttonStyle(.plain).padding(.horizontal, Space.md).padding(.vertical, 8)
                .accessibilityIdentifier("panel-pending")
            }
            divider
            footer.padding(.horizontal, Space.xs).padding(.vertical, 6)
        }
        .frame(width: Self.width)
        .background(Color.ratBase)
        .preferredColorScheme(.dark)
        .tint(Color.ratAccent)
        .accessibilityElement(children: .contain)
        .accessibilityIdentifier("control-center")
    }

    private var divider: some View { Rectangle().fill(Color.ratHairline).frame(height: 1) }

    // MARK: protection

    private var protection: ControlCenter.Protection {
        fixedProtection ?? ControlCenter.protection(helperInstalled: enforcer.helperInstalled, helperOutdated: enforcer.helperOutdated,
                                 status: enforcer.status, denying: !ledger.deniedAppPaths.isEmpty || ledger.deniedCount > 0)
    }

    private var status: some View {
        let p = protection
        let tint: Color = p.tone == .on ? .ratSuccess : p.tone == .warning ? .ratWarning : Palette.textSecondary
        return HStack(spacing: Space.sm) {
            Image(systemName: p.tone == .on ? "checkmark.shield.fill" : p.tone == .warning ? "exclamationmark.shield.fill" : "eye")
                .font(.system(size: 15, weight: .semibold))
                .foregroundStyle(p.tone == .monitoring ? Palette.textSecondary : Color.ratOnAccent)
                .frame(width: 32, height: 32)
                .background(p.tone == .monitoring ? Color.ratRaised : tint, in: RoundedRectangle(cornerRadius: Radius.sm))
            VStack(alignment: .leading, spacing: 2) {
                Text(p.title).font(Typo.rowTitle).foregroundStyle(Palette.text)
                    .accessibilityIdentifier("panel-protection")
                Text(p.detail).font(Typo.caption).foregroundStyle(Palette.textSecondary).lineLimit(2)
                    .fixedSize(horizontal: false, vertical: true)
                    .accessibilityIdentifier("panel-protection-detail")
            }
            Spacer(minLength: 0)
            if let fix = p.fix {
                Button(fix == .installHelper ? "Install…" : fix == .updateHelper ? "Update…" : "Open…") {
                    WindowRoutes.shared.settingsTab = "Security"
                    open("settings")
                }
                .buttonStyle(MatteButtonStyle(fill: p.tone == .warning ? .ratWarning : .ratRaised, text: p.tone == .warning ? .ratOnAccent : Palette.text))
                .controlSize(.small)
                .help("Settings > Security")
                .accessibilityIdentifier("panel-fix")
            }
        }
        .accessibilityElement(children: .contain)
    }

    // MARK: traffic

    private var traffic: some View {
        VStack(alignment: .leading, spacing: Space.xs) {
            HStack(spacing: Space.xs) {
                Pill(kind: .up, text: settings.formatRate(ledger.rateOut)).accessibilityIdentifier("panel-rate-up")
                Pill(kind: .down, text: settings.formatRate(ledger.rateIn)).accessibilityIdentifier("panel-rate-down")
            }
            TrafficChart(range: .fiveMinutes, height: 56)
            HStack(spacing: 6) {
                Text("This session").foregroundStyle(Palette.textTertiary)
                Spacer()
                Text("↑ \(formatBytes(ledger.sessionOut))").foregroundStyle(Color.ratSent)
                Text("↓ \(formatBytes(ledger.sessionIn))").foregroundStyle(Color.ratReceived)
            }
            .font(Typo.caption.monospacedDigit())
            .accessibilityElement(children: .combine)
            .accessibilityIdentifier("panel-session")
        }
    }

    // MARK: route

    private var route: ControlCenter.Route {
        fixedRoute ?? ControlCenter.route(internetTunnel: ledger.routes.internetTunnel, tunnelNames: ledger.routes.tunnelNames,
                            tunnelServers: ledger.tunnelServers, openWarp: ledger.openWarp, proxies: ledger.routes.proxies)
    }

    private var routeRow: some View {
        HStack(spacing: Space.xs) {
            switch route {
            case let .vpn(name, country):
                Image(systemName: "lock.shield").foregroundStyle(Color.ratVPN).frame(width: 18)
                Text("Through \(name)").foregroundStyle(Palette.text).lineLimit(1)
                Spacer(minLength: 4)
                if let c = country {
                    FlagView(code: c, height: 13)
                    Text(Countries.name(c)).foregroundStyle(Palette.textSecondary).lineLimit(1)
                }
            case let .proxy(text):
                Image(systemName: "arrow.triangle.branch").foregroundStyle(Color.ratProxy).frame(width: 18)
                Text(text).foregroundStyle(Palette.text).lineLimit(1).truncationMode(.middle)
                Spacer(minLength: 0)
            case .direct:
                Image(systemName: "globe").foregroundStyle(Palette.textSecondary).frame(width: 18)
                Text("Direct, no VPN").foregroundStyle(Palette.textSecondary)
                Spacer(minLength: 0)
            }
        }
        .font(Typo.body)
        .accessibilityElement(children: .combine)
        .accessibilityIdentifier("panel-route")
    }

    // MARK: apps

    private var activity: some View {
        let active = ControlCenter.activeApps(ledger.apps, hideLocal: settings.hideLocal)
        return VStack(alignment: .leading, spacing: 2) {
            Text("Active now").font(Typo.sectionHeader).foregroundStyle(Palette.textTertiary)
                .padding(.horizontal, Space.xs).padding(.bottom, 2)
            if active.isEmpty {
                Text("No app is sending or receiving").font(Typo.caption).foregroundStyle(Palette.textTertiary)
                    .padding(.horizontal, Space.xs).padding(.vertical, 6)
                    .accessibilityIdentifier("panel-quiet")
            }
            ForEach(active, id: \.app.id) { a in
                ActiveAppRow(app: a.app, rx: a.rx, tx: a.tx) {
                    WindowRoutes.shared.monitorApp = a.app.id
                    open("monitor")
                }
            }
        }
    }

    // MARK: mode and profile

    private var controls: some View {
        VStack(alignment: .leading, spacing: Space.xs) {
            ModeSwitch(mode: Binding(get: { rules.silentMode }, set: { rules.silentMode = $0 }))
            HStack {
                Text("Profile").font(Typo.body).foregroundStyle(Palette.textSecondary)
                Spacer()
                Menu {
                    ForEach(rules.ruleSet.profiles) { p in
                        Button { rules.activate(p.id) } label: {
                            if p.id == rules.ruleSet.activeProfileID { Label(p.name, systemImage: "checkmark") } else { Text(p.name) }
                        }
                    }
                } label: {
                    Label(rules.activeProfile?.name ?? "None", systemImage: rules.activeProfile?.symbol ?? "person.crop.circle")
                }
                .menuStyle(.borderlessButton).fixedSize()
                .accessibilityIdentifier("panel-profile")
            }
        }
    }

    // MARK: windows

    private var footer: some View {
        HStack(spacing: 2) {
            FooterButton(title: "Monitor", symbol: "network", id: "panel-open-monitor") { open("monitor") }
            FooterButton(title: "Rules", symbol: "list.bullet.rectangle", id: "panel-open-rules") { open("rules") }
            FooterButton(title: "Settings", symbol: "gearshape", id: "panel-open-settings") { open("settings") }
            Spacer(minLength: 0)
            FooterButton(title: "Quit", symbol: "power", id: "panel-quit", iconOnly: true) { quit() }
                .help("Quit Rat")
        }
    }
}

/// Alert / Silent Allow / Silent Deny across the panel's width: a matte track, the chosen mode filled with the
/// accent (dark text), the others quiet. Each segment is a button reporting value 1 while chosen (`panel-mode`).
private struct ModeSwitch: View {
    @Binding var mode: SilentMode
    @State private var hovered: SilentMode?

    var body: some View {
        HStack(spacing: 2) {
            ForEach(SilentMode.allCases) { m in
                let on = m == mode
                Button { mode = m } label: {
                    Text(ControlCenter.title(m))
                        .font(Typo.caption.weight(.semibold))
                        .foregroundStyle(on ? Color.ratOnAccent : hovered == m ? Palette.text : Palette.textSecondary)
                        .frame(maxWidth: .infinity).padding(.vertical, 6)
                        .background(on ? Color.ratAccent : hovered == m ? Color.ratHover : .clear, in: RoundedRectangle(cornerRadius: Radius.sm - 2))
                        .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
                .onHover { hovered = $0 ? m : (hovered == m ? nil : hovered) }
                .accessibilityLabel(ControlCenter.title(m))
                .accessibilityValue(on ? "1" : "0")
                .accessibilityAddTraits(on ? .isSelected : [])
            }
        }
        .padding(2)
        .background(Color.ratSurface, in: RoundedRectangle(cornerRadius: Radius.sm))
        .help("Alert asks about new connections; Silent Allow and Silent Deny decide without asking")
        .accessibilityElement(children: .contain)
        .accessibilityLabel("Mode")
        .accessibilityIdentifier("panel-mode")
    }
}

/// One app moving data: its icon, name and the last pass's rates. A click opens the monitor on it.
private struct ActiveAppRow: View {
    let app: AppEntry
    let rx: Double
    let tx: Double
    let action: () -> Void
    @State private var hovered = false
    @ObservedObject private var settings = AppSettings.shared

    var body: some View {
        Button(action: action) {
            HStack(spacing: Space.xs) {
                Image(nsImage: app.identity.icon).resizable().interpolation(.high).frame(width: 18, height: 18)
                Text(app.identity.name).font(Typo.body).foregroundStyle(Palette.text).lineLimit(1).truncationMode(.middle)
                Spacer(minLength: Space.xs)
                Text("↑ \(settings.formatRate(tx))").foregroundStyle(tx > 0 ? Color.ratSent : Palette.textTertiary)
                    .frame(minWidth: 70, alignment: .trailing)
                Text("↓ \(settings.formatRate(rx))").foregroundStyle(rx > 0 ? Color.ratReceived : Palette.textTertiary)
                    .frame(minWidth: 74, alignment: .trailing)
            }
            .font(Typo.caption.monospacedDigit())
            .padding(.horizontal, Space.xs).padding(.vertical, 5)
            .background(hovered ? Color.ratHover : .clear, in: RoundedRectangle(cornerRadius: Radius.sm))
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .onHover { hovered = $0 }
        .help("Show \(app.identity.name) in the Network Monitor")
        .accessibilityElement(children: .combine)
        .accessibilityLabel("\(app.identity.name), sent \(settings.formatRate(tx)), received \(settings.formatRate(rx))")
        .accessibilityIdentifier("panel-app-\(app.identity.name)")
    }
}

private struct FooterButton: View {
    let title: String
    let symbol: String
    let id: String
    var iconOnly = false
    let action: () -> Void
    @State private var hovered = false

    var body: some View {
        Button(action: action) {
            Group {
                if iconOnly { Image(systemName: symbol) } else { Label(title, systemImage: symbol) }
            }
            .font(Typo.caption.weight(.medium))
            .foregroundStyle(hovered ? Palette.text : Palette.textSecondary)
            .padding(.horizontal, 8).padding(.vertical, 6)
            .background(hovered ? Color.ratHover : .clear, in: RoundedRectangle(cornerRadius: Radius.sm))
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .onHover { hovered = $0 }
        .accessibilityLabel(title)
        .accessibilityIdentifier(id)
    }
}
