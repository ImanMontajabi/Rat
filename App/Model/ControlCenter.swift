import Foundation
import RatEnforce
import RatMonitor
import RatFilterCore

/// What the menu bar panel (Control Center, Little Snitch's name for it) says, worked out from the ledger, the
/// helper's status and the routes: no numbers of its own, so it never shows anything Rat does not know.
enum ControlCenter {
    /// Whether denying is enforced. Monitoring works without the helper; blocking does not, so the panel never
    /// says "on" unless the daemon is running, is this copy's, and pf holds Rat's anchor while there is something to block.
    struct Protection: Equatable {
        enum Tone: Equatable { case on, monitoring, warning }
        /// What the panel offers to put it right.
        enum Fix: Equatable { case installHelper, updateHelper, openSecurity }
        var tone: Tone
        var title: String
        var detail: String
        var fix: Fix?
    }

    /// `denying`: some app, process or connection is denied (so something should be blocked).
    static func protection(helperInstalled: Bool, helperOutdated: Bool, status: EnforcerStatus?, denying: Bool) -> Protection {
        guard helperInstalled else {
            return denying
                ? Protection(tone: .warning, title: "Monitoring only", detail: "Deny is not enforced: the firewall helper is not installed", fix: .installHelper)
                : Protection(tone: .monitoring, title: "Monitoring only", detail: "Install the firewall helper to block what you deny", fix: .installHelper)
        }
        if helperOutdated {
            return Protection(tone: .warning, title: "Firewall helper needs an update", detail: "Update it in Settings > Security", fix: .updateHelper)
        }
        guard let st = status else {
            return Protection(tone: .warning, title: "Firewall helper not running", detail: denying ? "Deny is not enforced" : "Deny will not be enforced until it runs", fix: .openSecurity)
        }
        if let issue = st.pfIssue, !issue.isEmpty {
            return Protection(tone: .warning, title: "Firewall needs attention", detail: issue, fix: .openSecurity)
        }
        if denying && !(st.pfEnabled && st.anchorHooked) {
            return Protection(tone: .warning, title: "Firewall not hooked", detail: "pf is off or skips Rat's rules: repair it in Settings > Security", fix: .openSecurity)
        }
        let blocked = st.blockedPorts + (st.blockedLoopbackPorts ?? 0)
        let detail = blocked > 0 ? "Blocking \(blocked) connection\(blocked == 1 ? "" : "s")"
            : denying ? "Ready to block what you deny" : "Nothing denied"
        return Protection(tone: .on, title: "Firewall on", detail: detail, fix: nil)
    }

    /// How the Internet leaves this Mac: through a full-tunnel VPN (its name and, when known, the country of its
    /// server), a system proxy, or directly.
    enum Route: Equatable {
        case vpn(name: String, country: String?)
        case proxy(String)
        case direct
    }

    static func route(internetTunnel: String?, tunnelNames: [String: String], tunnelServers: [String: TunnelServer],
                      openWarp: OpenWarpStatus?, proxies: [NetworkRoutes.ProxyEndpoint]) -> Route {
        if let iface = internetTunnel {
            let name = tunnelNames[iface] ?? iface
            var country: String?
            if case let .country(c)? = tunnelServers[iface] { country = c }
            // OpenWarp says where its exit is (Cloudflare's `loc`) when the carrier's address does not.
            if country == nil, let w = openWarp, w.connected, w.interface == iface, let loc = w.loc { country = loc }
            return .vpn(name: name, country: country.map { $0.uppercased() })
        }
        if let p = proxies.first(where: { !$0.isLoopback }) ?? proxies.first {
            return .proxy("\(p.kind.rawValue) proxy \(p.host):\(p.port)")
        }
        return .direct
    }

    /// The apps moving data right now, busiest first: the last pass's rate of each (`AppEntry.rates`), local-only
    /// apps left out while local traffic is hidden.
    static func activeApps(_ apps: [AppEntry], limit: Int = 4, hideLocal: Bool) -> [(app: AppEntry, rx: Double, tx: Double)] {
        apps.compactMap { a -> (app: AppEntry, rx: Double, tx: Double)? in
            guard let r = a.rates.last, r.rx + r.tx > 0, !(hideLocal && a.onlyLocal) else { return nil }
            return (a, r.rx, r.tx)
        }
        .sorted { ($0.rx + $0.tx, $1.app.identity.name) > ($1.rx + $1.tx, $0.app.identity.name) }
        .prefix(limit).map { $0 }
    }

    /// What waits for the user: connection alerts and rules to review, as one line ("2 alerts · 1 rule to review").
    static func pending(alerts: Int, unapproved: Int) -> String? {
        var parts: [String] = []
        if alerts > 0 { parts.append("\(alerts) alert\(alerts == 1 ? "" : "s") waiting") }
        if unapproved > 0 { parts.append("\(unapproved) rule\(unapproved == 1 ? "" : "s") to review") }
        return parts.isEmpty ? nil : parts.joined(separator: " · ")
    }

    /// The modes' short names for the panel's segmented control.
    static func title(_ m: SilentMode) -> String { m == .off ? "Alert" : m == .allow ? "Silent Allow" : "Silent Deny" }
}

/// Lets the menu bar panel steer windows it opens: the monitor onto one app, Settings onto one tab.
@MainActor
final class WindowRoutes: ObservableObject {
    static let shared = WindowRoutes()
    @Published var monitorApp: String?
    @Published var settingsTab: String?
}
