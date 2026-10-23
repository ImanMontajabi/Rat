import Foundation
import RatMonitor

/// Marks connections that leave through a VPN tunnel or go to a system proxy (#2): "via VPN (Windscribe)",
/// "via System HTTPS Proxy (proxy.example:3128)". Refreshed every few seconds, so a VPN that just connected is
/// marked from the next refresh on.
@MainActor
final class RouteMarker {
    private(set) var tunnelAddresses: [String: String] = [:]
    private(set) var tunnelNames: [String: String] = [:]
    private(set) var proxies: [NetworkRoutes.ProxyEndpoint] = []
    private var proxyAddresses: [String: Set<String>] = [:]
    private var pendingLookups = Set<String>()
    private var lastRefresh = Date.distantPast
    static let interval: TimeInterval = 5

    /// `helperTunnels` is the root helper's view (it sees VPN daemons running as root).
    func refresh(now: Date = Date(), helperTunnels: [String: String]?) {
        guard now.timeIntervalSince(lastRefresh) >= Self.interval else { return }
        lastRefresh = now
        tunnelAddresses = NetworkRoutes.tunnelAddresses()
        let interfaces = Set(tunnelAddresses.values)
        if interfaces.isEmpty { tunnelNames = [:] } else {
            let services = NetworkRoutes.vpnServiceNames()
            let owners = (helperTunnels ?? [:]).merging(NetworkRoutes.tunnelOwners()) { helper, _ in helper }
            tunnelNames = Dictionary(uniqueKeysWithValues: interfaces.map { ($0, Self.name(interface: $0, service: services[$0], owner: owners[$0])) })
        }
        proxies = NetworkRoutes.systemProxies()
        for p in proxies where !p.isLoopback && !isIPLiteral(p.host) && proxyAddresses[p.host] == nil && pendingLookups.insert(p.host).inserted {
            let host = p.host
            Task.detached {
                let addrs = Self.addresses(of: host)
                await MainActor.run { self.proxyAddresses[host] = addrs; self.pendingLookups.remove(host) }
            }
        }
    }

    /// The VPN's name: the service name from System Settings, a known VPN app in the owner's path, the owner's app
    /// name, or the interface itself.
    static func name(interface: String, service: String?, owner: String?) -> String {
        if let owner, let known = NetworkRoutes.knownApp(inPath: owner) { return known }
        if let service, !service.isEmpty { return service }
        if let owner, ProcessGrouping.bundleRoot(of: owner) != nil { return AppIdentity.resolve(processPath: owner).name }
        return interface
    }

    func route(localAddress: String, remoteAddress: String, remotePort: Int) -> String? {
        if let iface = tunnelAddresses[localAddress] { return "via VPN (\(tunnelNames[iface] ?? iface))" }
        if let p = NetworkRoutes.proxy(for: remoteAddress, port: remotePort, among: proxies, addresses: proxyAddresses) {
            return "via System \(p.kind.rawValue) Proxy (\(p.host):\(p.port))"
        }
        return nil
    }

    /// Test hook: fixed tunnels and proxies instead of the Mac's.
    func set(tunnelAddresses: [String: String], tunnelNames: [String: String], proxies: [NetworkRoutes.ProxyEndpoint], proxyAddresses: [String: Set<String>] = [:]) {
        self.tunnelAddresses = tunnelAddresses; self.tunnelNames = tunnelNames; self.proxies = proxies; self.proxyAddresses = proxyAddresses
        lastRefresh = .distantFuture
    }

    nonisolated static func addresses(of host: String) -> Set<String> {
        var hints = addrinfo(); hints.ai_socktype = SOCK_STREAM
        var res: UnsafeMutablePointer<addrinfo>?
        guard getaddrinfo(host, nil, &hints, &res) == 0, let first = res else { return [] }
        defer { freeaddrinfo(res) }
        var out = Set<String>()
        for ai in sequence(first: first, next: { $0.pointee.ai_next }) {
            var h = [CChar](repeating: 0, count: Int(NI_MAXHOST))
            if getnameinfo(ai.pointee.ai_addr, ai.pointee.ai_addrlen, &h, socklen_t(h.count), nil, 0, NI_NUMERICHOST) == 0 { out.insert(String(cString: h)) }
        }
        return out
    }
}
