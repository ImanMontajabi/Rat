import Foundation

/// The destination a client asks a local proxy for, read from the first bytes it sends over loopback (before the
/// proxy encrypts anything, for example into an SSH tunnel).
public struct ProxyRequest: Equatable, Sendable {
    public enum Kind: String, Codable, Sendable {
        case httpConnect = "HTTP CONNECT", httpProxy = "HTTP", socks5 = "SOCKS5", socks4 = "SOCKS4", socks4a = "SOCKS4a"
    }
    public var kind: Kind
    /// Domain name or IP literal, as the client sent it (IPv6 without brackets).
    public var host: String
    public var port: Int
}

public enum ProxyHandshake {
    /// Parses one client-to-proxy payload. Strict: only well-formed proxy requests are accepted, so ordinary
    /// loopback traffic (a local web server's `GET /`, a database protocol) is never mistaken for one.
    public static func parse(_ p: [UInt8]) -> ProxyRequest? {
        guard let first = p.first else { return nil }
        switch first {
        case 0x05: return socks5(p) ?? socks5AfterGreeting(p)
        case 0x04: return socks4(p)
        default: return http(p)
        }
    }

    /// SOCKS5 request: VER CMD=CONNECT RSV=0 ATYP DST.ADDR DST.PORT, and nothing after it.
    static func socks5(_ p: [UInt8]) -> ProxyRequest? {
        guard p.count >= 10, p[0] == 5, p[1] == 1, p[2] == 0 else { return nil }
        let host: String, end: Int
        switch p[3] {
        case 1:
            end = 8
            host = p[4..<8].map(String.init).joined(separator: ".")
        case 3:
            let n = Int(p[4])
            end = 5 + n
            guard n > 0, p.count >= end + 2, let name = hostname(Array(p[5..<end])) else { return nil }
            host = name
        case 4:
            end = 20
            guard p.count >= 22 else { return nil }
            host = ipv6(Array(p[4..<20]))
        default:
            return nil
        }
        guard p.count == end + 2 else { return nil }
        let port = Int(p[end]) << 8 | Int(p[end + 1])
        guard port > 0 else { return nil }
        return ProxyRequest(kind: .socks5, host: host, port: port)
    }

    /// Some clients send the method greeting (VER NMETHODS METHODS) and the request in one segment.
    static func socks5AfterGreeting(_ p: [UInt8]) -> ProxyRequest? {
        guard p.count >= 3, p[0] == 5 else { return nil }
        let n = Int(p[1])
        guard n > 0, p.count > 2 + n else { return nil }
        return socks5(Array(p[(2 + n)...]))
    }

    /// SOCKS4: VN=4 CD=CONNECT DSTPORT DSTIP USERID 0, and for SOCKS4a (DSTIP 0.0.0.x) the domain and a 0.
    static func socks4(_ p: [UInt8]) -> ProxyRequest? {
        guard p.count >= 9, p[0] == 4, p[1] == 1 else { return nil }
        let port = Int(p[2]) << 8 | Int(p[3])
        guard port > 0, let userEnd = p[8...].firstIndex(of: 0), userEnd - 8 <= 255 else { return nil }
        if p[4] == 0, p[5] == 0, p[6] == 0, p[7] != 0 {
            let start = userEnd + 1
            guard let nameEnd = p[start...].firstIndex(of: 0), nameEnd == p.count - 1,
                  let name = hostname(Array(p[start..<nameEnd])) else { return nil }
            return ProxyRequest(kind: .socks4a, host: name, port: port)
        }
        guard userEnd == p.count - 1, p[4] != 0 else { return nil }
        return ProxyRequest(kind: .socks4, host: p[4..<8].map(String.init).joined(separator: "."), port: port)
    }

    private static let methods: Set<String> = ["GET", "POST", "PUT", "HEAD", "DELETE", "OPTIONS", "PATCH"]

    /// `CONNECT host:port HTTP/1.x`, or a request with an absolute URI (`GET http://host[:port]/…`), which only
    /// proxies receive. A plain `GET /path` (with a Host header) is a request to a local server, not to a proxy.
    static func http(_ p: [UInt8]) -> ProxyRequest? {
        // The request line can be cut off by the capture length; the authority is all that is needed.
        let line = p.prefix(1024).prefix { $0 != 0x0d && $0 != 0x0a }
        guard line.allSatisfy({ $0 >= 0x20 && $0 < 0x7f }) else { return nil }
        let parts = String(decoding: line, as: UTF8.self).split(separator: " ", omittingEmptySubsequences: false)
        guard parts.count >= 2 else { return nil }
        let method = String(parts[0]), target = String(parts[1])
        let complete = line.count < min(p.count, 1024)   // the line ended (CR or LF) within what was read
        if complete { guard parts.count == 3, parts[2].hasPrefix("HTTP/1.") else { return nil } }
        if method == "CONNECT" {
            guard complete || parts.count == 3, let (host, port) = authority(target, defaultPort: nil) else { return nil }
            return ProxyRequest(kind: .httpConnect, host: host, port: port)
        }
        guard methods.contains(method) else { return nil }
        let lower = target.lowercased()
        let scheme: (prefix: String, port: Int)? = lower.hasPrefix("http://") ? ("http://", 80) : lower.hasPrefix("https://") ? ("https://", 443) : nil
        guard let scheme else { return nil }
        let rest = target.dropFirst(scheme.prefix.count)
        // The authority must be complete: it ends at the path, query or fragment, or at the end of a complete line.
        guard let stop = rest.firstIndex(where: { "/?#".contains($0) }) ?? (complete || parts.count == 3 ? rest.endIndex : nil) else { return nil }
        var auth = String(rest[..<stop])
        if let at = auth.lastIndex(of: "@") { auth = String(auth[auth.index(after: at)...]) }   // user:password@ is dropped
        guard let (host, port) = authority(auth, defaultPort: scheme.port) else { return nil }
        return ProxyRequest(kind: .httpProxy, host: host, port: port)
    }

    /// `host:port`, `[v6]:port`, or `host` when a default port applies.
    static func authority(_ s: String, defaultPort: Int?) -> (String, Int)? {
        var host = s, portText: String?
        if s.hasPrefix("[") {
            guard let close = s.firstIndex(of: "]") else { return nil }
            host = String(s[s.index(after: s.startIndex)..<close])
            let after = s[s.index(after: close)...]
            if !after.isEmpty { guard after.hasPrefix(":") else { return nil }; portText = String(after.dropFirst()) }
            var a = in6_addr()
            guard inet_pton(AF_INET6, host, &a) == 1 else { return nil }
        } else if let colon = s.lastIndex(of: ":") {
            host = String(s[..<colon]); portText = String(s[s.index(after: colon)...])
        }
        let port: Int
        if let portText { guard let v = Int(portText), portText.allSatisfy(\.isNumber) else { return nil }; port = v }
        else { guard let d = defaultPort else { return nil }; port = d }
        guard (1...65535).contains(port), !host.isEmpty else { return nil }
        if s.hasPrefix("[") { return (host, port) }
        guard let name = hostname(Array(host.utf8)) else { return nil }
        return (name, port)
    }

    /// A DNS name or IPv4 literal (letters, digits, `-`, `_`, `.`), lowercased.
    static func hostname(_ b: [UInt8]) -> String? {
        guard !b.isEmpty, b.count <= 253 else { return nil }
        for c in b {
            let ok = (c >= 0x30 && c <= 0x39) || (c >= 0x41 && c <= 0x5a) || (c >= 0x61 && c <= 0x7a) || c == 0x2d || c == 0x2e || c == 0x5f
            if !ok { return nil }
        }
        let s = String(decoding: b, as: UTF8.self).lowercased()
        guard !s.hasPrefix("."), !s.contains("..") else { return nil }
        return s
    }

    static func ipv6(_ b: [UInt8]) -> String {
        var a = in6_addr()
        withUnsafeMutableBytes(of: &a) { $0.copyBytes(from: b) }
        var buf = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
        return inet_ntop(AF_INET6, &a, &buf, socklen_t(buf.count)).map { String(cString: $0) } ?? ""
    }
}
