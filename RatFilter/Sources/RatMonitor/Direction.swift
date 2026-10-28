import Foundation

/// Who started a connection. One socket does not say: a TCP connection a listener accepted looks like any other.
/// A peer started it when its local port is one a listening socket holds on the same address (or on any address);
/// the listener can belong to another process (launchd listens and hands the connection to the service it starts).
/// UDP has no listeners or handshakes, so a UDP socket is never called incoming.
public enum SocketDirection {
    /// The sockets with `incoming` set where a peer started them.
    public static func mark(_ conns: [ObservedConnection]) -> [ObservedConnection] {
        var anyAddress = Set<Int>(), byAddress = Set<String>()
        for c in conns where c.proto == .tcp && c.tcpState == "LISTEN" && c.localPort != 0 {
            if isAny(c.localAddress) { anyAddress.insert(c.localPort) } else { byAddress.insert("\(c.localAddress)|\(c.localPort)") }
        }
        guard !anyAddress.isEmpty || !byAddress.isEmpty else { return conns }
        return conns.map { c in
            guard c.proto == .tcp, c.tcpState != "LISTEN", c.isOutbound, c.localPort != 0 else { return c }
            var c = c
            c.incoming = anyAddress.contains(c.localPort) || byAddress.contains("\(c.localAddress)|\(c.localPort)")
                || byAddress.contains("\(unmapped(c.localAddress))|\(c.localPort)")
            return c
        }
    }

    private static func isAny(_ a: String) -> Bool { a.isEmpty || a == "*" || a == "0.0.0.0" || a == "::" }

    /// An IPv4 address an IPv6 socket reports as `::ffff:a.b.c.d`.
    private static func unmapped(_ a: String) -> String { a.lowercased().hasPrefix("::ffff:") && a.contains(".") ? String(a.dropFirst(7)) : a }
}

/// Long-lived sockets that mostly receive: a download, a server push (Server-Sent Events, a notification channel) or
/// a media stream. Rat sees byte counts only, so it cannot tell which: inside TLS, an event stream and a file look the
/// same. A socket is a stream once it has been open for `minimumAge`, received at least `minimumBytesIn` and
/// `ratio` times what it sent, and is still receiving (its count grew in the last `quietLimit`).
public struct StreamDetector {
    public var minimumAge: TimeInterval
    public var minimumBytesIn: UInt64
    public var ratio: UInt64
    public var quietLimit: TimeInterval

    private struct Seen { var first: Date; var bytesIn: UInt64; var grew: Date }
    private var seen: [String: Seen] = [:]

    public init(minimumAge: TimeInterval = 30, minimumBytesIn: UInt64 = 32 * 1024, ratio: UInt64 = 8, quietLimit: TimeInterval = 10) {
        self.minimumAge = minimumAge; self.minimumBytesIn = minimumBytesIn; self.ratio = ratio; self.quietLimit = quietLimit
    }

    /// Notes a socket's counters on this pass and says whether it is a stream. A socket seen for the first time with
    /// bytes already counted is timed from now: how long it was open before is not known.
    public mutating func update(_ key: String, bytesIn: UInt64, bytesOut: UInt64, now: Date) -> Bool {
        var s = seen[key] ?? Seen(first: now, bytesIn: bytesIn, grew: .distantPast)
        if bytesIn > s.bytesIn { s.grew = now }
        s.bytesIn = bytesIn
        seen[key] = s
        return now.timeIntervalSince(s.first) >= minimumAge && bytesIn >= minimumBytesIn
            && bytesOut <= bytesIn / max(ratio, 1) && now.timeIntervalSince(s.grew) <= quietLimit
    }

    /// Forgets the sockets that are gone.
    public mutating func keep(only keys: Set<String>) { seen = seen.filter { keys.contains($0.key) } }

    public var count: Int { seen.count }

    /// One socket, for `update`.
    public static func key(pid: Int32, proto: ObservedConnection.Proto, localPort: Int, remoteAddress: String, remotePort: Int) -> String {
        "\(pid)|\(proto.rawValue)|\(localPort)|\(remoteAddress)|\(remotePort)"
    }
}
