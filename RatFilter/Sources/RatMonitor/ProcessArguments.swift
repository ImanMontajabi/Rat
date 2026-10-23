import Darwin
import Foundation

/// What a command line says about where a process connects through a proxy (`KERN_PROCARGS2`). Only the
/// destination hosts of URL arguments and the proxy settings are kept; other arguments and environment variables
/// (tokens, passwords) are never stored.
public struct ProcessArguments: Equatable, Sendable {
    public struct Target: Equatable, Hashable, Sendable {
        public var host: String; public var port: Int
        public init(host: String, port: Int) { self.host = host; self.port = port }
    }
    public struct Endpoint: Equatable, Hashable, Sendable {
        public var host: String; public var port: Int
        public init(host: String, port: Int) { self.host = host; self.port = port }
    }

    /// `scheme://host[:port]` arguments (curl, wget, git-remote-https, brew's curl).
    public var targets: [Target]
    /// Proxies named by `--proxy`/`-x`/`--socks5*` arguments or `http_proxy`, `https_proxy`, `all_proxy`.
    public var proxies: [Endpoint]

    public init(targets: [Target], proxies: [Endpoint]) { self.targets = targets; self.proxies = proxies }

    /// Reads another process's arguments and environment (same user, or root).
    public static func read(pid: pid_t) -> ProcessArguments? {
        var mib: [Int32] = [CTL_KERN, KERN_PROCARGS2, pid]
        var size = 0
        guard sysctl(&mib, 3, nil, &size, nil, 0) == 0, size > 0 else { return nil }
        var buf = [UInt8](repeating: 0, count: size)
        guard sysctl(&mib, 3, &buf, &size, nil, 0) == 0 else { return nil }
        return parse(Array(buf.prefix(size)))
    }

    /// `KERN_PROCARGS2` layout: argc (int32), the executable path, padding NULs, argv[0..argc), then environment.
    public static func parse(_ b: [UInt8]) -> ProcessArguments? {
        guard b.count > 4 else { return nil }
        let argc = Int(b[0]) | Int(b[1]) << 8 | Int(b[2]) << 16 | Int(b[3]) << 24
        var i = 4
        while i < b.count, b[i] != 0 { i += 1 }   // executable path
        while i < b.count, b[i] == 0 { i += 1 }
        var strings: [String] = []
        while i < b.count {
            let start = i
            while i < b.count, b[i] != 0 { i += 1 }
            strings.append(String(decoding: b[start..<i], as: UTF8.self))
            i += 1
            if strings.count >= argc + 512 { break }
        }
        guard strings.count >= argc else { return nil }
        let argv = Array(strings.prefix(argc)), env = strings.dropFirst(argc)
        return from(arguments: argv, environment: Array(env))
    }

    public static func from(arguments argv: [String], environment env: [String]) -> ProcessArguments {
        var targets: [Target] = [], proxies: [Endpoint] = []
        let proxyFlags: Set<String> = ["-x", "--proxy", "--socks4", "--socks4a", "--socks5", "--socks5-hostname", "--preproxy", "-e"]
        var i = 1
        while i < argv.count {
            let a = argv[i]
            if proxyFlags.contains(a), i + 1 < argv.count {
                // wget takes `-e use_proxy=yes -e https_proxy=…`.
                let v = argv[i + 1]
                let value = a == "-e" ? (v.split(separator: "=", maxSplits: 1).last.map(String.init) ?? "") : v
                if a != "-e" || v.lowercased().contains("_proxy=") { if let e = endpoint(value) { proxies.append(e) } }
                i += 2; continue
            }
            if a.hasPrefix("--proxy="), let e = endpoint(String(a.dropFirst(8))) { proxies.append(e) }
            else if let t = url(a) { targets.append(t) }
            i += 1
        }
        for e in env {
            guard let eq = e.firstIndex(of: "=") else { continue }
            let key = e[..<eq].lowercased()
            guard ["http_proxy", "https_proxy", "all_proxy"].contains(key), let p = endpoint(String(e[e.index(after: eq)...])) else { continue }
            proxies.append(p)
        }
        return ProcessArguments(targets: Array(NSOrderedSet(array: targets).array as! [Target]), proxies: Array(NSOrderedSet(array: proxies).array as! [Endpoint]))
    }

    private static let defaultPorts = ["http": 80, "https": 443, "ftp": 21, "ws": 80, "wss": 443, "git": 9418, "ssh": 22]

    /// `scheme://[user@]host[:port][/…]` for the schemes that make network connections.
    static func url(_ s: String) -> Target? {
        guard let sep = s.range(of: "://") else { return nil }
        let scheme = s[..<sep.lowerBound].lowercased()
        guard let def = defaultPorts[scheme] else { return nil }
        guard let (host, port) = authority(String(s[sep.upperBound...]), defaultPort: def) else { return nil }
        return Target(host: host, port: port)
    }

    /// A proxy setting: `host:port`, `scheme://host:port`, `socks5h://user:pw@[::1]:1080/`.
    static func endpoint(_ s: String) -> Endpoint? {
        var rest = s.trimmingCharacters(in: .whitespaces)
        var def = 1080
        if let sep = rest.range(of: "://") {
            def = rest[..<sep.lowerBound].lowercased().hasPrefix("http") ? 80 : 1080
            rest = String(rest[sep.upperBound...])
        }
        return authority(rest, defaultPort: def).map { Endpoint(host: $0.0, port: $0.1) }
    }

    private static func authority(_ s: String, defaultPort: Int) -> (String, Int)? {
        var a = String(s.prefix { !"/?#".contains($0) })
        if let at = a.lastIndex(of: "@") { a = String(a[a.index(after: at)...]) }
        var host = a, port = defaultPort
        if a.hasPrefix("[") {
            guard let close = a.firstIndex(of: "]") else { return nil }
            host = String(a[a.index(after: a.startIndex)..<close])
            let after = a[a.index(after: close)...]
            if after.hasPrefix(":") { guard let p = Int(after.dropFirst()) else { return nil }; port = p }
        } else if let colon = a.lastIndex(of: ":") {
            guard let p = Int(a[a.index(after: colon)...]) else { return nil }
            host = String(a[..<colon]); port = p
        }
        let allowed = CharacterSet.alphanumerics.union(CharacterSet(charactersIn: ".-_:"))
        guard !host.isEmpty, host.count <= 253, (1...65535).contains(port), host.unicodeScalars.allSatisfy(allowed.contains) else { return nil }
        return (host.lowercased(), port)
    }

    /// Whether a proxy setting points at this Mac (`127.0.0.1`, `localhost`, `::1`) on `port`.
    public func usesLocalProxy(port: Int) -> Bool {
        proxies.contains { $0.port == port && ["127.0.0.1", "localhost", "::1", "0.0.0.0"].contains($0.host) || $0.port == port && $0.host.hasPrefix("127.") }
    }
}
