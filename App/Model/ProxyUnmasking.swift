import Foundation
import RatMonitor
import RatEnforce

/// The local proxy a connection went through: which program listens on the loopback port and, when it has exactly
/// one connection off the Mac (`ssh -D` to its server), that server.
struct ProxyHop: Hashable {
    var kind: String            // "SOCKS5", "HTTP CONNECT", "HTTP", "command line"
    var process: String         // "ssh"
    var listener: String        // "127.0.0.1:1080"
    var server: String?
    var serverGeo: GeoPoint?

    var label: String { "via \(process) proxy (\(listener)\(server.map { " → " + $0 } ?? ""))" }
    /// The tag next to the unmasked destination: "Proxy · ssh".
    var badge: String { "Proxy · \(process)" }
}

/// A destination unmasked from a client's loopback connection to a local proxy.
struct ProxiedRemote: Equatable {
    var pid: Int32
    var path: String
    var clientPort: Int
    var proxyPort: Int
    var host: String
    var port: Int
    var hop: ProxyHop
    /// The client's loopback socket still exists. Only live sockets are ever handed to the daemon: the port of a
    /// closed one may already belong to another program's connection.
    var live = true
}

enum ProxyUnmasking {
    /// Connections that closed this recently are still shown, so a one-second `curl` is not missed between passes.
    static let linger: TimeInterval = 10

    static func maskKey(pid: Int32, localPort: Int, remotePort: Int) -> String { "\(pid)|\(localPort)|\(remotePort)" }

    /// Destinations behind local proxies, from the helper's lo0 capture (`flows`) and, for connections it did not
    /// see, from the client's command line (`curl -x 127.0.0.1:8080 https://…`). `masked` names the loopback
    /// sockets these replace in the connection list.
    static func unmask(flows: [ProxiedFlow], conns: [ObservedConnection], now: Date,
                       arguments: (Int32) -> ProcessArguments?) -> (remotes: [ProxiedRemote], masked: Set<String>) {
        var byPID: [Int32: [ObservedConnection]] = [:]
        var listeners: [Int: ObservedConnection] = [:]
        for c in conns {
            byPID[c.pid, default: []].append(c)
            if c.tcpState == "LISTEN", c.localPort != 0, listeners[c.localPort] == nil { listeners[c.localPort] = c }
        }
        /// The proxy's one connection off the Mac, if it has exactly one server. A plain forwarding proxy's one
        /// connection is the destination itself, not a server it tunnels through: same address, or the
        /// destination's port from a program that is not a known tunnel (ssh, Tor, Clash reach their server on
        /// a port of their own).
        func server(of pid: Int32?, path: String?, destination: String, port: Int) -> String? {
            guard let pid else { return nil }
            let off = (byPID[pid] ?? []).filter { $0.proto == .tcp && $0.isOutbound && !ProxyWatch.isLoopback($0.remoteAddress) }
            guard Set(off.map(\.remoteAddress)).count == 1, let c = off.first else { return nil }
            if c.remoteAddress == destination.lowercased() { return nil }
            if Set(off.map(\.remotePort)) == [port], path.flatMap(NetworkRoutes.localProxyProgram(inPath:)) == nil { return nil }
            return c.remoteAddress
        }
        func name(_ path: String?) -> String { path.map { ($0 as NSString).lastPathComponent } ?? "local" }

        var remotes: [ProxiedRemote] = [], masked = Set<String>()
        var proxyPorts = Set<Int>()
        for f in flows where f.closed.map({ now.timeIntervalSince($0) < linger }) ?? true {
            proxyPorts.insert(f.proxyPort)
            let hop = ProxyHop(kind: f.kind.rawValue, process: name(f.proxyPath), listener: f.ipv6 ? "[::1]:\(f.proxyPort)" : "127.0.0.1:\(f.proxyPort)",
                               server: server(of: f.proxyPID, path: f.proxyPath, destination: f.host, port: f.port))
            remotes.append(ProxiedRemote(pid: f.clientPID, path: f.clientPath, clientPort: f.clientPort, proxyPort: f.proxyPort, host: f.host, port: f.port, hop: hop,
                                         live: f.closed == nil))
            masked.insert(maskKey(pid: f.clientPID, localPort: f.clientPort, remotePort: f.proxyPort))
        }

        // Fallback: a loopback connection to a proxy the helper did not see (no helper, or opened before it ran).
        var argsCache: [Int32: ProcessArguments?] = [:]
        for c in conns where c.proto == .tcp && c.tcpState != "LISTEN" && ProxyWatch.isLoopback(c.remoteAddress) && c.remotePort != 0 {
            let key = maskKey(pid: c.pid, localPort: c.localPort, remotePort: c.remotePort)
            guard !masked.contains(key) else { continue }
            let listener = listeners[c.remotePort]
            guard listener?.pid != c.pid else { continue }   // a process talking to itself
            if argsCache[c.pid] == nil { argsCache[c.pid] = .some(arguments(c.pid)) }
            guard let args = argsCache[c.pid] ?? nil, !args.targets.isEmpty,
                  proxyPorts.contains(c.remotePort) || args.usesLocalProxy(port: c.remotePort) else { continue }
            let address = c.remoteAddress.contains(":") ? "[\(c.remoteAddress)]:\(c.remotePort)" : "\(c.remoteAddress):\(c.remotePort)"
            for t in args.targets {
                let hop = ProxyHop(kind: "command line", process: name(listener?.processPath), listener: address,
                                   server: server(of: listener?.pid, path: listener?.processPath, destination: t.host, port: t.port))
                remotes.append(ProxiedRemote(pid: c.pid, path: c.processPath, clientPort: c.localPort, proxyPort: c.remotePort, host: t.host, port: t.port, hop: hop))
            }
            masked.insert(key)
        }
        return (remotes, masked)
    }
}

/// Addresses for proxied destination names, looked up in the background so a pass never waits for DNS.
final class ProxyResolver: @unchecked Sendable {
    private let lock = NSLock()
    private var cache: [String: (address: String?, at: Date)] = [:]
    private var pending = Set<String>()
    private let lookup: @Sendable (String) -> String?

    init(lookup: @escaping @Sendable (String) -> String? = ProxyResolver.systemLookup) { self.lookup = lookup }

    /// The address if known; otherwise starts a lookup and returns nil (or the literal itself for an IP).
    func address(for host: String, enabled: Bool) -> String? {
        if isIPLiteral(host) { return host }
        guard enabled else { return nil }
        return lock.withLock { () -> String? in
            if let c = cache[host], Date().timeIntervalSince(c.at) < 600 { return c.address }
            if pending.insert(host).inserted {
                Task.detached { [lookup] in
                    let a = lookup(host)
                    self.lock.withLock { self.cache[host] = (a, Date()); self.pending.remove(host) }
                }
            }
            return cache[host]?.address
        }
    }

    static func systemLookup(_ host: String) -> String? {
        var hints = addrinfo(); hints.ai_socktype = SOCK_STREAM; hints.ai_flags = AI_ADDRCONFIG
        var res: UnsafeMutablePointer<addrinfo>?
        guard getaddrinfo(host, nil, &hints, &res) == 0, let first = res else { return nil }
        defer { freeaddrinfo(res) }
        var host = [CChar](repeating: 0, count: Int(NI_MAXHOST))
        guard getnameinfo(first.pointee.ai_addr, first.pointee.ai_addrlen, &host, socklen_t(host.count), nil, 0, NI_NUMERICHOST) == 0 else { return nil }
        return String(cString: host)
    }
}
