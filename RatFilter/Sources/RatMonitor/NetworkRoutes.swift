import Darwin
import Foundation
import SystemConfiguration

/// Which path a connection takes off the Mac: through a VPN tunnel (its socket's own address is on a utun or
/// ipsec interface, so split tunnels are told apart per socket) or to a system proxy (its server is the proxy
/// configured in System Settings). Everything here works without an entitlement.
public enum NetworkRoutes {
    // MARK: tunnel interfaces

    static let tunnelPrefixes = ["utun", "ipsec", "ppp", "tun", "tap", "wg"]

    public static func isTunnel(_ interface: String) -> Bool {
        tunnelPrefixes.contains { interface.hasPrefix($0) && interface.dropFirst($0.count).allSatisfy(\.isNumber) && interface.count > $0.count }
    }

    /// Addresses of tunnel interfaces → interface name. Link-local addresses are left out: every interface has one
    /// and no Internet connection uses it.
    public static func tunnelAddresses() -> [String: String] {
        var out: [String: String] = [:]
        var list: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&list) == 0, let first = list else { return out }
        defer { freeifaddrs(list) }
        for p in sequence(first: first, next: { $0.pointee.ifa_next }) {
            let name = String(cString: p.pointee.ifa_name)
            guard isTunnel(name), let sa = p.pointee.ifa_addr else { continue }
            let family = Int32(sa.pointee.sa_family)
            guard family == AF_INET || family == AF_INET6 else { continue }
            var host = [CChar](repeating: 0, count: Int(NI_MAXHOST))
            let len = socklen_t(family == AF_INET ? MemoryLayout<sockaddr_in>.size : MemoryLayout<sockaddr_in6>.size)
            guard getnameinfo(sa, len, &host, socklen_t(host.count), nil, 0, NI_NUMERICHOST) == 0 else { continue }
            let a = String(cString: host)
            if a.lowercased().hasPrefix("fe80") { continue }
            out[a] = name
        }
        return out
    }

    /// The interface the kernel sends packets for `address` through, from the routing table (what
    /// `route -n get <address>` prints as `interface:`). With a full-tunnel VPN the Internet's routes
    /// (`0/1` and `128.0/1`, or a scoped default) point at the tunnel, so this names it. Nil when the address is
    /// not a literal or no route matches.
    public static func routeInterface(to address: String) -> String? {
        var dst = sockaddr_storage()
        let length: Int
        if var a4 = in_addr() as in_addr?, inet_pton(AF_INET, address, &a4) == 1 {
            var sin = sockaddr_in(); sin.sin_len = UInt8(MemoryLayout<sockaddr_in>.size); sin.sin_family = sa_family_t(AF_INET); sin.sin_addr = a4
            length = MemoryLayout<sockaddr_in>.size
            withUnsafeBytes(of: sin) { src in withUnsafeMutableBytes(of: &dst) { $0.copyMemory(from: src) } }
        } else if var a6 = in6_addr() as in6_addr?, inet_pton(AF_INET6, address, &a6) == 1 {
            var sin6 = sockaddr_in6(); sin6.sin6_len = UInt8(MemoryLayout<sockaddr_in6>.size); sin6.sin6_family = sa_family_t(AF_INET6); sin6.sin6_addr = a6
            length = MemoryLayout<sockaddr_in6>.size
            withUnsafeBytes(of: sin6) { src in withUnsafeMutableBytes(of: &dst) { $0.copyMemory(from: src) } }
        } else { return nil }

        let fd = socket(PF_ROUTE, SOCK_RAW, 0)
        guard fd >= 0 else { return nil }
        defer { close(fd) }
        var timeout = timeval(tv_sec: 1, tv_usec: 0)
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))

        // Request: header, RTA_DST (the address), RTA_IFP (an empty link address: "tell me the interface").
        func roundup(_ n: Int) -> Int { n > 0 ? 1 + ((n - 1) | (MemoryLayout<UInt32>.size - 1)) : MemoryLayout<UInt32>.size }
        var ifp = sockaddr_dl(); ifp.sdl_len = UInt8(MemoryLayout<sockaddr_dl>.size); ifp.sdl_family = sa_family_t(AF_LINK)
        let header = MemoryLayout<rt_msghdr>.size
        var buf = [UInt8](repeating: 0, count: header + roundup(length) + roundup(MemoryLayout<sockaddr_dl>.size))
        let seq = Int32.random(in: 1..<Int32.max)
        var rtm = rt_msghdr()
        rtm.rtm_msglen = UInt16(buf.count); rtm.rtm_version = UInt8(RTM_VERSION); rtm.rtm_type = UInt8(RTM_GET)
        rtm.rtm_addrs = RTA_DST | RTA_IFP; rtm.rtm_flags = RTF_UP | RTF_HOST; rtm.rtm_seq = seq; rtm.rtm_pid = getpid()
        buf.withUnsafeMutableBytes { b in
            withUnsafeBytes(of: rtm) { b.copyMemory(from: $0) }
            withUnsafeBytes(of: dst) { UnsafeMutableRawBufferPointer(rebasing: b[header..<header + length]).copyMemory(from: UnsafeRawBufferPointer(rebasing: $0[0..<length])) }
            withUnsafeBytes(of: ifp) { src in
                let at = header + roundup(length)
                UnsafeMutableRawBufferPointer(rebasing: b[at..<at + src.count]).copyMemory(from: src)
            }
        }
        guard buf.withUnsafeBytes({ write(fd, $0.baseAddress, $0.count) }) == buf.count else { return nil }

        // Reply: the same header with every address the kernel filled in, in RTA_* bit order.
        var reply = [UInt8](repeating: 0, count: 2048)
        for _ in 0..<8 {
            let n = reply.withUnsafeMutableBytes { read(fd, $0.baseAddress, $0.count) }
            guard n >= header else { return nil }
            let r = reply.withUnsafeBytes { $0.loadUnaligned(as: rt_msghdr.self) }
            guard r.rtm_seq == seq, r.rtm_pid == getpid(), r.rtm_type == UInt8(RTM_GET) else { continue }
            guard r.rtm_errno == 0 else { return nil }
            var at = header
            for bit in 0..<Int(RTAX_MAX) {
                guard r.rtm_addrs & (1 << bit) != 0, at < n else { continue }
                let len = Int(reply[at])
                if 1 << bit == RTA_IFP, at + 1 < n, reply[at + 1] == UInt8(AF_LINK) {
                    let dl = reply.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: at, as: sockaddr_dl.self) }
                    let nameLength = Int(dl.sdl_nlen)
                    let start = at + 8   // sdl_len, family, index (2), type, nlen, alen, slen
                    guard nameLength > 0, start + nameLength <= n else { return nil }
                    return String(decoding: reply[start..<start + nameLength], as: UTF8.self)
                }
                at += roundup(len)
            }
            return nil
        }
        return nil
    }

    /// The tunnel interface that carries the Internet (a full-tunnel VPN), if one does: the interface the
    /// kernel would route a public address through.
    public static func internetTunnel() -> String? {
        for probe in ["1.1.1.1", "2606:4700:4700::1111"] {
            if let i = routeInterface(to: probe), isTunnel(i) { return i }
        }
        return nil
    }

    /// Whether a socket leaves the Mac outside a VPN tunnel (what "Only through a VPN" cuts). A server inside the
    /// local network (`isLocal`) never does. A socket bound to a tunnel's address goes through that tunnel; one
    /// bound to another address (Wi-Fi, Ethernet) does not, even while a VPN is up (it was opened before the VPN, or
    /// the VPN splits). A socket with no address of its own goes where the routing table sends its server
    /// (`route`; nil asks for the Internet's route, for a socket not connected to a server).
    public static func leavesOutsideTunnel(localAddress: String, remoteAddress: String, tunnels: [String: String],
                                           isLocal: (String) -> Bool, route: (String?) -> String?) -> Bool {
        if !remoteAddress.isEmpty, isLocal(remoteAddress) { return false }
        // Bound to loopback, it can reach nothing else.
        if tunnels[localAddress] != nil || localAddress == "::1" || localAddress.hasPrefix("127.") { return false }
        guard ["", "*", "0.0.0.0", "::"].contains(localAddress), !tunnels.isEmpty else { return true }
        guard let iface = route(remoteAddress.isEmpty ? nil : remoteAddress) else { return true }
        return !isTunnel(iface)
    }

    /// Tunnel interface → path of the process holding its kernel control socket (the VPN client that opened
    /// `utunN`). Root sees every process; a user only their own.
    public static func tunnelOwners(pids: [pid_t] = ConnectionSampler.allPIDs()) -> [String: String] {
        var out: [String: String] = [:]
        for pid in pids {
            for fd in ConnectionSampler.socketFDs(of: pid) {
                var info = socket_fdinfo()
                let r = proc_pidfdinfo(pid, fd, PROC_PIDFDSOCKETINFO, &info, Int32(MemoryLayout<socket_fdinfo>.size))
                guard r == Int32(MemoryLayout<socket_fdinfo>.size), Int(info.psi.soi_kind) == SOCKINFO_KERN_CTL else { continue }
                let kc = info.psi.soi_proto.pri_kern_ctl
                let name = withUnsafeBytes(of: kc.kcsi_name) { String(decoding: $0.prefix { $0 != 0 }, as: UTF8.self) }
                guard kc.kcsi_unit > 0, let prefix = ["com.apple.net.utun_control": "utun", "com.apple.net.ipsec_control": "ipsec"][name] else { continue }
                let iface = "\(prefix)\(kc.kcsi_unit - 1)"
                if out[iface] == nil { out[iface] = ConnectionSampler.path(of: pid) }
            }
        }
        return out
    }

    /// Names of VPN services configured in System Settings, by the tunnel interface they are up on.
    public static func vpnServiceNames() -> [String: String] {
        guard let store = SCDynamicStoreCreate(nil, "Rat" as CFString, nil, nil) else { return [:] }
        var out: [String: String] = [:]
        for proto in ["IPv4", "IPv6"] {
            let pattern = "State:/Network/Service/[^/]+/\(proto)" as CFString
            guard let keys = SCDynamicStoreCopyKeyList(store, pattern) as? [String] else { continue }
            for key in keys {
                guard let state = SCDynamicStoreCopyValue(store, key as CFString) as? [String: Any],
                      let iface = state["InterfaceName"] as? String, isTunnel(iface) else { continue }
                let id = key.split(separator: "/").dropFirst(3).first.map(String.init) ?? ""
                let setup = SCDynamicStoreCopyValue(store, "Setup:/Network/Service/\(id)" as CFString) as? [String: Any]
                if let name = setup?["UserDefinedName"] as? String, !name.isEmpty { out[iface] = name }
            }
        }
        return out
    }

    // MARK: known VPN and proxy apps (issue #2)

    /// Lowercase names of VPN and proxy apps and daemons. Matched as whole words in a process path, so `tor`
    /// does not match "Monitor" and `pia` not "Spiad".
    static let knownApps: [String] = [
        "1.1.1.1", "air vpn", "airvpn", "atlas vpn", "best vpn", "betternet", "black vpn", "boringtun", "bullet vpn", "cfw",
        "cisco anyconnect", "clash", "clashx", "cloudflare warp", "cloudflared", "cyberghost", "expressvpn", "f5 vpn", "f5access",
        "fastestvpn", "flash vpn", "forticlient", "free vpn", "ghostery", "globalprotect", "hamachi", "hiddify", "hidemyass",
        "hotspot shield", "hysteria", "ipvanish", "ivacy", "ivacy vpn", "keepsolid vpn", "lantern", "lightning vpn", "liquid vpn",
        "loon", "mullvad", "mullvad-daemon", "mullvad-vpn", "naiveproxy", "nekoray", "nordlynx", "nordvpn", "obfs4proxy",
        "octane vpn", "omega vpn", "onion browser", "openconnect", "openvpn", "orbot", "perfect privacy", "perfect-privacy", "pia",
        "private internet access", "proton vpn", "protonvpn", "psiphon", "pulse secure", "pulsesecure", "purevpn", "quantumult",
        "riseup vpn", "riseup-vpn", "rocket vpn", "safervpn", "secure vpn", "shadowrocket", "shadowsocks", "sing-box", "sky vpn",
        "snowflake", "softether", "spideroak", "stash", "strongvpn", "sunset vpn", "sunset-vpn", "super vpn", "surfshark", "surge",
        "tailscale", "tailscaled", "thunder vpn", "tor", "tor browser", "trojan", "trust.zone", "tunnelbear", "tunnelblick",
        "turbo vpn", "urban vpn", "v2ray", "viscosity", "vpn master", "vpn proxy master", "vpn unlimited", "vyprvpn", "warp",
        "wg-quick", "windscribe", "wireguard", "zenmate", "zerotier",
    ]

    /// How a few names are written by their makers; the rest are title-cased.
    static let displayNames: [String: String] = [
        "nordvpn": "NordVPN", "expressvpn": "ExpressVPN", "protonvpn": "Proton VPN", "proton vpn": "Proton VPN", "purevpn": "PureVPN",
        "ipvanish": "IPVanish", "vyprvpn": "VyprVPN", "cyberghost": "CyberGhost", "tunnelbear": "TunnelBear", "clashx": "ClashX",
        "openvpn": "OpenVPN", "wireguard": "WireGuard", "zerotier": "ZeroTier", "pia": "PIA", "globalprotect": "GlobalProtect",
        "forticlient": "FortiClient", "hidemyass": "HideMyAss", "airvpn": "AirVPN", "strongvpn": "StrongVPN", "safervpn": "SaferVPN",
        "fastestvpn": "FastestVPN", "v2ray": "V2Ray", "sing-box": "sing-box", "tailscaled": "Tailscale", "mullvad-daemon": "Mullvad",
        "mullvad-vpn": "Mullvad", "cloudflared": "Cloudflare", "warp": "Cloudflare WARP", "1.1.1.1": "Cloudflare WARP",
        "wg-quick": "WireGuard", "boringtun": "WireGuard", "nordlynx": "NordVPN", "tor": "Tor", "cfw": "Clash for Windows",
    ]

    private static let patterns: [(name: String, regex: NSRegularExpression)] = knownApps.sorted { $0.count > $1.count }.compactMap { n in
        let words = n.split(whereSeparator: { " -".contains($0) }).map { NSRegularExpression.escapedPattern(for: String($0)) }
        let body = words.joined(separator: "[ ._-]?")
        return (try? NSRegularExpression(pattern: "(?<![a-z0-9])\(body)(?![a-z0-9])")).map { (n, $0) }
    }

    /// The known VPN or proxy app a process path belongs to, by its maker's spelling ("Windscribe", "NordVPN").
    public static func knownApp(inPath path: String) -> String? {
        let lower = path.lowercased()
        let range = NSRange(lower.startIndex..., in: lower)
        guard let hit = patterns.first(where: { $0.regex.firstMatch(in: lower, range: range) != nil })?.name else { return nil }
        return displayNames[hit] ?? hit.split(separator: " ").map { $0.prefix(1).uppercased() + $0.dropFirst() }.joined(separator: " ")
    }

    // MARK: local proxies

    /// Executables that run a proxy or tunnel on the Mac (`ssh -D`, Tor, Clash, mitmproxy, …), by lowercase name.
    static let localProxyPrograms: [String: String] = [
        "ssh": "ssh", "autossh": "autossh", "tor": "Tor", "mitmproxy": "mitmproxy", "mitmdump": "mitmproxy", "mitmweb": "mitmproxy",
        "privoxy": "Privoxy", "polipo": "Polipo", "squid": "Squid", "tinyproxy": "tinyproxy", "3proxy": "3proxy",
        "clash": "Clash", "clash-meta": "Clash", "mihomo": "Clash", "v2ray": "V2Ray", "xray": "Xray", "sing-box": "sing-box",
        "hysteria": "Hysteria", "trojan": "Trojan", "trojan-go": "Trojan", "naive": "NaiveProxy", "ss-local": "Shadowsocks",
        "sslocal": "Shadowsocks", "gost": "gost", "glider": "glider", "brook": "Brook", "tuic-client": "TUIC", "redsocks": "redsocks",
        "wireproxy": "wireproxy", "cloudflared": "cloudflared", "obfs4proxy": "obfs4proxy", "lyrebird": "Tor", "snowflake-client": "Tor",
        "proxychains4": "proxychains", "dnscrypt-proxy": "dnscrypt-proxy",
    ]

    /// The local proxy a loopback listener belongs to: a known proxy program, or a known VPN/proxy app
    /// ("ClashX", "Hiddify"). Nil for anything else (a dev server on port 3000 is no proxy).
    public static func localProxyProgram(inPath path: String) -> String? {
        let exe = (path as NSString).lastPathComponent.lowercased()
        return localProxyPrograms[exe] ?? knownApp(inPath: path)
    }

    // MARK: system proxies

    public struct ProxyEndpoint: Equatable, Hashable, Sendable {
        public enum Kind: String, Sendable { case http = "HTTP", https = "HTTPS", socks = "SOCKS" }
        public var kind: Kind
        public var host: String
        public var port: Int
        public init(kind: Kind, host: String, port: Int) { self.kind = kind; self.host = host; self.port = port }
        public var isLoopback: Bool { ["127.0.0.1", "localhost", "::1"].contains(host.lowercased()) || host.hasPrefix("127.") }
    }

    /// Enabled HTTP, HTTPS and SOCKS proxies from System Settings (`SCDynamicStoreCopyProxies`). Automatic
    /// configuration (PAC files) is not evaluated.
    public static func systemProxies() -> [ProxyEndpoint] {
        (SCDynamicStoreCopyProxies(nil) as? [String: Any]).map(proxies(from:)) ?? []
    }

    public static func proxies(from d: [String: Any]) -> [ProxyEndpoint] {
        var out: [ProxyEndpoint] = []
        for (kind, prefix) in [(ProxyEndpoint.Kind.http, "HTTP"), (.https, "HTTPS"), (.socks, "SOCKS")] {
            guard (d["\(prefix)Enable"] as? NSNumber)?.boolValue == true, let host = d["\(prefix)Proxy"] as? String, !host.isEmpty,
                  let port = (d["\(prefix)Port"] as? NSNumber)?.intValue, (1...65535).contains(port) else { continue }
            out.append(ProxyEndpoint(kind: kind, host: host, port: port))
        }
        return out
    }

    /// Whether PAC (automatic proxy configuration) is on, which Rat cannot evaluate.
    public static func usesAutomaticProxy() -> Bool {
        let d = SCDynamicStoreCopyProxies(nil) as? [String: Any]
        return (d?["ProxyAutoConfigEnable"] as? NSNumber)?.boolValue == true || (d?["ProxyAutoDiscoveryEnable"] as? NSNumber)?.boolValue == true
    }

    /// The system proxy a connection goes to: its server address and port are a proxy's (`addresses` maps each
    /// proxy host to the addresses it resolves to; a loopback proxy matches 127.0.0.1 and ::1).
    public static func proxy(for remoteAddress: String, port: Int, among endpoints: [ProxyEndpoint], addresses: [String: Set<String>]) -> ProxyEndpoint? {
        endpoints.first { e in
            guard e.port == port else { return false }
            if e.isLoopback { return remoteAddress.hasPrefix("127.") || remoteAddress == "::1" }
            return e.host == remoteAddress || (addresses[e.host]?.contains(remoteAddress) ?? false)
        }
    }
}
