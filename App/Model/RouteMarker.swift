import Foundation
import RatMonitor
import RatEnforce

/// The path a connection takes off the Mac, shown as a tag in the tree and the inspector.
enum RouteTag: Hashable {
    /// Its socket's address is on a tunnel interface: the traffic leaves through the VPN.
    case vpn(name: String, interface: String)
    /// It talks to the proxy set in System Settings, not to the server itself.
    case systemProxy(kind: String, host: String, port: Int)
    /// A loopback connection to a local proxy program whose destination was not seen (`ssh -D`, Tor, Clash).
    case localProxy(program: String, listener: String)
    /// The VPN client's own connection to its server: the tunnel's carrier, outside the tunnel.
    case vpnServer(name: String)

    var isVPN: Bool { if case .vpn = self { return true }; return false }
    var isProxy: Bool {
        switch self {
        case .systemProxy, .localProxy: return true
        case .vpn, .vpnServer: return false
        }
    }

    /// Short tag: "VPN · Windscribe · utun3", "Proxy · System HTTPS", "Proxy · ssh".
    var badge: String {
        switch self {
        case let .vpn(name, interface): return name == interface ? "VPN · \(interface)" : "VPN · \(name) · \(interface)"
        case let .systemProxy(kind, _, _): return "Proxy · System \(kind)"
        case let .localProxy(program, _): return "Proxy · \(program)"
        case let .vpnServer(name): return "VPN server · \(name)"
        }
    }

    /// Sentence form, as in alerts: "via VPN (Windscribe)".
    var label: String {
        switch self {
        case let .vpn(name, _): return "via VPN (\(name))"
        case let .systemProxy(kind, host, port): return "via System \(kind) Proxy (\(host):\(port))"
        case let .localProxy(program, listener): return "via \(program) proxy (\(listener))"
        case let .vpnServer(name): return "\(name)'s connection to its VPN server"
        }
    }

    /// For narrow rows: the VPN's name without its interface ("VPN · Windscribe").
    var shortBadge: String {
        if case let .vpn(name, interface) = self { return "VPN · \(name == interface ? interface : name)" }
        return badge
    }

    var help: String {
        switch self {
        case let .vpn(_, interface): return "This connection leaves through the VPN tunnel (\(interface))."
        case .systemProxy: return "This app talks to the system proxy, not to the server itself: the address and location shown are the proxy's, and a rule for a domain cannot match."
        case .localProxy: return "This app talks to a local proxy on this Mac. Where the proxy sends it was not seen: the firewall helper reads the proxy request when it is installed."
        case .vpnServer: return "The VPN client's own connection to its server. It carries the tunnel, so it does not go through it."
        }
    }
}

/// Marks connections that leave through a VPN tunnel or go to a system proxy (#2): "via VPN (Windscribe)",
/// "via System HTTPS Proxy (proxy.example:3128)". Refreshed every few seconds, so a VPN that just connected is
/// marked from the next refresh on.
@MainActor
final class RouteMarker {
    private(set) var tunnelAddresses: [String: String] = [:]
    private(set) var tunnelNames: [String: String] = [:]
    private(set) var proxies: [NetworkRoutes.ProxyEndpoint] = []
    /// The tunnel the Internet's routes point at (a full-tunnel VPN), from the routing table.
    private(set) var internetTunnel: String?
    /// Executable paths of the VPN clients holding the tunnels → the VPN's name.
    private(set) var tunnelClients: [String: String] = [:]
    /// Tunnel interface → the executable path of the VPN client holding it.
    private(set) var tunnelOwners: [String: String] = [:]
    /// Interface the routing table picks per remote address, for sockets without an address of their own.
    private var routeCache: [String: String?] = [:]
    private var proxyAddresses: [String: Set<String>] = [:]
    private var pendingLookups = Set<String>()
    private var lastRefresh = Date.distantPast
    static let interval: TimeInterval = 5

    /// `helperTunnels` is the root helper's view (it sees VPN daemons running as root).
    func refresh(now: Date = Date(), helperTunnels: [String: String]?) {
        guard now.timeIntervalSince(lastRefresh) >= Self.interval else { return }
        lastRefresh = now
        tunnelAddresses = NetworkRoutes.tunnelAddresses()
        routeCache = [:]
        let interfaces = Set(tunnelAddresses.values)
        if interfaces.isEmpty { tunnelNames = [:]; tunnelClients = [:]; tunnelOwners = [:]; internetTunnel = nil } else {
            let services = NetworkRoutes.vpnServiceNames()
            let owners = (helperTunnels ?? [:]).merging(NetworkRoutes.tunnelOwners()) { helper, _ in helper }
            tunnelNames = Dictionary(uniqueKeysWithValues: interfaces.map { ($0, Self.name(interface: $0, service: services[$0], owner: owners[$0])) })
            tunnelClients = [:]
            for i in interfaces { if let o = owners[i] { tunnelClients[o] = tunnelNames[i] } }
            tunnelOwners = owners.filter { interfaces.contains($0.key) }
            internetTunnel = NetworkRoutes.internetTunnel().flatMap { interfaces.contains($0) ? $0 : nil }
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

    /// The path one connection takes. The socket's own address decides first: bound to a tunnel's address, it
    /// goes through that tunnel (split tunnels are told apart per socket; a socket opened on Wi-Fi before the VPN
    /// came up stays on Wi-Fi). A socket without an address of its own goes where the routing table sends its
    /// server. The VPN client's own connection outside the tunnel is the tunnel's carrier.
    func route(localAddress: String, remoteAddress: String, remotePort: Int, processPath: String? = nil) -> RouteTag? {
        if let iface = tunnelAddresses[localAddress] { return .vpn(name: tunnelNames[iface] ?? iface, interface: iface) }
        if let path = processPath, let name = tunnelClients[path], HostNames.hasNetworkName(remoteAddress) { return .vpnServer(name: name) }
        if Self.unspecified(localAddress), HostNames.hasNetworkName(remoteAddress), !tunnelAddresses.isEmpty {
            if routeCache[remoteAddress] == nil { routeCache[remoteAddress] = .some(NetworkRoutes.routeInterface(to: remoteAddress)) }
            if let iface = routeCache[remoteAddress] ?? nil, Set(tunnelAddresses.values).contains(iface) {
                return .vpn(name: tunnelNames[iface] ?? iface, interface: iface)
            }
        }
        if let p = NetworkRoutes.proxy(for: remoteAddress, port: remotePort, among: proxies, addresses: proxyAddresses) {
            return .systemProxy(kind: p.kind.rawValue, host: p.host, port: p.port)
        }
        return nil
    }

    /// A loopback connection to another program's listener that is a proxy (`ssh -D 1080`, Tor on 9050).
    static func localProxy(remoteAddress: String, remotePort: Int, pid: Int32, listener: (pid: Int32, path: String)?) -> RouteTag? {
        guard ProxyWatch.isLoopback(remoteAddress), let listener, listener.pid != pid,
              let program = NetworkRoutes.localProxyProgram(inPath: listener.path) else { return nil }
        return .localProxy(program: program, listener: remoteAddress.contains(":") ? "[\(remoteAddress)]:\(remotePort)" : "\(remoteAddress):\(remotePort)")
    }

    /// No address of its own: not bound, or bound to the wildcard.
    static func unspecified(_ address: String) -> Bool { ["", "*", "0.0.0.0", "::"].contains(address) }

    /// Test hook: fixed tunnels and proxies instead of the Mac's.
    func set(tunnelAddresses: [String: String], tunnelNames: [String: String], proxies: [NetworkRoutes.ProxyEndpoint], proxyAddresses: [String: Set<String>] = [:],
             tunnelClients: [String: String] = [:], routes: [String: String] = [:], tunnelOwners: [String: String] = [:]) {
        self.tunnelAddresses = tunnelAddresses; self.tunnelNames = tunnelNames; self.proxies = proxies; self.proxyAddresses = proxyAddresses
        self.tunnelClients = tunnelClients; self.tunnelOwners = tunnelOwners
        routeCache = routes.mapValues { .some($0) }
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
