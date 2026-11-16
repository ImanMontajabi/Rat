import Darwin
import Foundation

/// OpenWarp, the companion Cloudflare WARP client (github.com/ImanMontajabi/OpenWarp), as Rat and its daemon see it.
///
/// Its root daemon (`/Library/PrivilegedHelperTools/com.local.openwarp`, a copy of the CLI outside the app bundle)
/// creates the utun itself and carries it over QUIC (MASQUE) or WireGuard from one *unconnected* UDP socket
/// (`*:port <-> *:*`): the kernel never records the server, so no socket table names the Cloudflare endpoint.
/// The daemon's control socket answers `GET /v1/status` for any local user; that status names the tunnel's
/// interface, its endpoint and (from OpenWarp 0.2) where it exits (`colo`/`loc`). The endpoint is an anycast
/// address, so a geolocation database's answer for it (Canada) says nothing about where traffic leaves.
/// docs/ARCHITECTURE.md §23.
public struct OpenWarpStatus: Equatable, Sendable {
    public static let helperPath = "/Library/PrivilegedHelperTools/com.local.openwarp"
    public static let socketPath = "/var/run/openwarp.sock"
    public static let appPath = "/Applications/OpenWarp.app"
    public static let bundleIdentifier = "local.openwarp.app"
    /// The largest status read: the real one is about 1.5 KB.
    static let maxResponse = 64 << 10

    public struct Endpoint: Equatable, Sendable {
        public var address: String
        public var port: Int
        public init(address: String, port: Int) { self.address = address; self.port = port }
    }

    /// The daemon process that answered (the control socket's peer), whose sockets carry the tunnel.
    public var pid: pid_t
    public var connected: Bool
    /// "warp", "warp+doh", "doh", "proxy", …
    public var mode: String
    /// "MASQUE (HTTP/3)" or "WireGuard".
    public var transport: String?
    /// The utun it created (absent in proxy and DNS-only modes).
    public var interface: String?
    public var endpoint: Endpoint?
    /// IATA code of the Cloudflare data centre the tunnel exits at ("DUS").
    public var colo: String?
    /// ISO 3166-1 alpha-2 country of the exit ("DE").
    public var loc: String?

    public init(pid: pid_t, connected: Bool, mode: String, transport: String? = nil, interface: String? = nil,
                endpoint: Endpoint? = nil, colo: String? = nil, loc: String? = nil) {
        self.pid = pid; self.connected = connected; self.mode = mode; self.transport = transport; self.interface = interface
        self.endpoint = endpoint; self.colo = colo; self.loc = loc
    }

    // MARK: parsing (untrusted input)

    private struct Wire: Decodable {
        struct Tunnel: Decodable { var `protocol`: String?; var endpoint: String? }
        var status: String
        var mode: String?
        var interface: String?
        var tunnel: Tunnel?
        var colo: String?
        var loc: String?
    }

    /// The status from the daemon's JSON. Every field is checked: a malformed one is dropped, not trusted.
    public static func parse(json: Data, pid: pid_t) -> OpenWarpStatus? {
        guard json.count <= maxResponse, let w = try? JSONDecoder().decode(Wire.self, from: json) else { return nil }
        let connected = w.status == "Connected"
        var s = OpenWarpStatus(pid: pid, connected: connected, mode: String((w.mode ?? "").prefix(16)))
        guard connected else { return s }
        if let i = w.interface, i.range(of: #"^utun[0-9]{1,4}$"#, options: .regularExpression) != nil { s.interface = i }
        s.transport = w.tunnel?.protocol.map { String($0.prefix(32)) }
        s.endpoint = w.tunnel?.endpoint.flatMap(endpoint)
        if let c = w.colo, letters(c, 3) { s.colo = c }
        if let l = w.loc, letters(l, 2), l != "XX", l != "T1" { s.loc = l }
        return s
    }

    /// The JSON body of an HTTP/1.x `200` response, else nil.
    public static func parse(http data: Data, pid: pid_t) -> OpenWarpStatus? {
        guard let split = data.range(of: Data("\r\n\r\n".utf8)) else { return nil }
        let head = String(decoding: data[..<split.lowerBound].prefix(512), as: UTF8.self)
        guard let line = head.split(separator: "\r\n").first, line.hasPrefix("HTTP/1."), line.split(separator: " ").dropFirst().first == "200" else { return nil }
        return parse(json: data[split.upperBound...], pid: pid)
    }

    /// "162.159.198.2:443" or "[2606:4700:d0::a29f:c001]:443": a numeric address and a port.
    public static func endpoint(_ text: String) -> Endpoint? {
        guard let colon = text.lastIndex(of: ":"), let port = Int(text[text.index(after: colon)...]), (1...65535).contains(port) else { return nil }
        var host = String(text[..<colon])
        if host.hasPrefix("["), host.hasSuffix("]") { host = String(host.dropFirst().dropLast()) }
        var v4 = in_addr(), v6 = in6_addr()
        guard inet_pton(AF_INET, host, &v4) == 1 || inet_pton(AF_INET6, host, &v6) == 1 else { return nil }
        return Endpoint(address: host, port: port)
    }

    static func letters(_ s: String, _ n: Int) -> Bool {
        s.utf8.count == n && s.utf8.allSatisfy { $0 >= 65 && $0 <= 90 }
    }

    // MARK: reading

    /// Asks the daemon for its status over its control socket. Nil unless the socket is a socket owned by `owner`
    /// (root) and the process answering it runs `peer` (OpenWarp's helper): another program cannot stand in for it.
    /// Waits at most `timeout` for each step, and reads at most `maxResponse` bytes.
    public static func read(socket path: String = socketPath, peer: String = helperPath, owner: uid_t = 0, timeout: TimeInterval = 0.25) -> OpenWarpStatus? {
        var st = stat()
        guard lstat(path, &st) == 0, (st.st_mode & S_IFMT) == S_IFSOCK, st.st_uid == owner else { return nil }
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { return nil }
        defer { close(fd) }
        var tv = timeval(tv_sec: Int(timeout), tv_usec: Int32((timeout - Double(Int(timeout))) * 1_000_000))
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
        var one: Int32 = 1
        setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, socklen_t(MemoryLayout<Int32>.size))
        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        let bytes = Array(path.utf8)
        guard bytes.count < MemoryLayout.size(ofValue: addr.sun_path) else { return nil }
        withUnsafeMutableBytes(of: &addr.sun_path) { raw in raw.copyBytes(from: bytes); raw[bytes.count] = 0 }
        let len = socklen_t(MemoryLayout<sockaddr_un>.size)
        let ok = withUnsafePointer(to: &addr) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { connect(fd, $0, len) } }
        guard ok == 0 else { return nil }
        var pid: pid_t = 0
        var pidLen = socklen_t(MemoryLayout<pid_t>.size)
        guard getsockopt(fd, SOL_LOCAL, LOCAL_PEERPID, &pid, &pidLen) == 0, pid > 0, ConnectionSampler.path(of: pid) == peer else { return nil }
        let request = Array("GET /v1/status HTTP/1.0\r\nHost: openwarp\r\n\r\n".utf8)
        guard request.withUnsafeBytes({ write(fd, $0.baseAddress, $0.count) }) == request.count else { return nil }
        var response = Data()
        var buf = [UInt8](repeating: 0, count: 8192)
        while response.count <= maxResponse {
            let n = buf.withUnsafeMutableBytes { Darwin.read(fd, $0.baseAddress, $0.count) }
            if n <= 0 { break }
            response.append(contentsOf: buf[0..<n])
        }
        guard response.count <= maxResponse else { return nil }
        return parse(http: response, pid: pid)
    }
}

/// The last OpenWarp status, read again at most every `interval` (the tunnel's endpoint and exit change only when it
/// reconnects) and only while the control socket exists. Safe from any thread.
public final class OpenWarpLink: @unchecked Sendable {
    public static let shared = OpenWarpLink()
    private let lock = NSLock()
    private var last: (at: Date, status: OpenWarpStatus?)?
    private let interval: TimeInterval
    private let reader: () -> OpenWarpStatus?
    private let present: () -> Bool

    public init(interval: TimeInterval = 5, present: @escaping () -> Bool = { access(OpenWarpStatus.socketPath, F_OK) == 0 },
                reader: @escaping () -> OpenWarpStatus? = { OpenWarpStatus.read() }) {
        self.interval = interval; self.present = present; self.reader = reader
    }

    public func current(now: Date = Date()) -> OpenWarpStatus? {
        if let l = lock.withLock({ last }), now.timeIntervalSince(l.at) < interval, now >= l.at { return l.status }
        let s = present() ? reader() : nil
        lock.withLock { last = (now, s) }
        return s
    }
}

/// Cloudflare WARP's endpoint ranges (the official client's and OpenWarp's, documented by Cloudflare for firewall
/// allow-lists). They are anycast: whichever data centre is nearest answers, so a database's country for them is
/// where the prefix is registered, not where a tunnel to them leads.
public enum CloudflareWARP {
    static let v4: [(UInt32, UInt32)] = [
        (0xA29F_C000, 24),   // 162.159.192.0/24  WireGuard
        (0xA29F_C100, 24),   // 162.159.193.0/24  WireGuard
        (0xA29F_C500, 24),   // 162.159.197.0/24  MASQUE
        (0xA29F_C600, 24),   // 162.159.198.0/24  MASQUE
    ]
    /// 2606:4700:d0::/48, 2606:4700:d1::/48, 2606:4700:102::/48 (the first six bytes).
    static let v6: [[UInt8]] = [[0x26, 0x06, 0x47, 0x00, 0x00, 0xD0], [0x26, 0x06, 0x47, 0x00, 0x00, 0xD1], [0x26, 0x06, 0x47, 0x00, 0x01, 0x02]]

    public static func isEndpoint(_ address: String) -> Bool {
        var a = in_addr()
        if inet_pton(AF_INET, address, &a) == 1 {
            let ip = UInt32(bigEndian: a.s_addr)
            return v4.contains { net, bits in ip >> (32 - bits) == net >> (32 - bits) }
        }
        var b = in6_addr()
        guard inet_pton(AF_INET6, address, &b) == 1 else { return false }
        let prefix = withUnsafeBytes(of: &b) { Array($0.prefix(6)) }
        return v6.contains(prefix)
    }
}

/// The tunnel client's own connection to its server, for a client that sends from an unconnected UDP socket.
public enum TunnelCarrier {
    /// The sockets of OpenWarp's daemon that carry its tunnel, named by the endpoint its status gives: an unconnected
    /// UDP socket (no peer, any local address but loopback) of the process that answered the status, while it is
    /// connected. Each becomes a connection to the endpoint marked `carrier`; everything else is unchanged.
    public static func resolve(_ conns: [ObservedConnection], openWarp: OpenWarpStatus?) -> [ObservedConnection] {
        guard let w = openWarp, w.connected, let e = w.endpoint else { return conns }
        return conns.map { c in
            guard c.pid == w.pid, isUnconnectedUDP(c) else { return c }
            var x = c
            x.remoteAddress = e.address; x.remotePort = e.port; x.carrier = true
            return x
        }
    }

    static func isUnconnectedUDP(_ c: ObservedConnection) -> Bool {
        c.proto == .udp && c.tcpState == nil && c.remotePort == 0 && ["", "*", "0.0.0.0", "::"].contains(c.remoteAddress)
            && c.localPort != 0 && !NetworkRoutes.isLoopback(c.localAddress)
    }
}

/// Where a tunnel leads, shared by Rat and its daemon so both judge "Only through a VPN in <country>" alike.
public enum TunnelPlacement {
    /// OpenWarp's tunnel goes to its endpoint; any other keeps the carriers found (`NetworkRoutes.carrierServers`).
    public static func carriers(of iface: String, found: [String], openWarp: OpenWarpStatus?) -> [String] {
        if let w = openWarp, w.connected, w.interface == iface, let e = w.endpoint { return [e.address] }
        return found
    }

    /// The country a tunnel exits in. OpenWarp's is the exit it reports (nil until it answered: unknown). A tunnel
    /// whose carriers are all Cloudflare WARP endpoints is unknown too: they are anycast. Otherwise the carriers'
    /// country (`NetworkRoutes.serverCountry`).
    public static func country(of iface: String, carriers: [String], lookup: (String) -> String?, openWarp: OpenWarpStatus?) -> String? {
        if let w = openWarp, w.connected, w.interface == iface { return w.loc }
        if !carriers.isEmpty, carriers.allSatisfy(CloudflareWARP.isEndpoint) { return nil }
        return NetworkRoutes.serverCountry(carriers, lookup: lookup)
    }

    /// The country a server is in for rules and the list: OpenWarp's exit for its endpoint, unknown for any other WARP
    /// endpoint (anycast), else the database's.
    public static func serverCountry(_ address: String, lookup: (String) -> String?, openWarp: OpenWarpStatus?) -> String? {
        if let w = openWarp, w.connected, w.endpoint?.address == address { return w.loc }
        if CloudflareWARP.isEndpoint(address) { return nil }
        return lookup(address)
    }
}
