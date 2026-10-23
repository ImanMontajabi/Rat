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
