import Darwin
import Foundation

/// The local network: connections to it are not judged by rules from alerts or the Rules window, only by the
/// process list's ✗/✓ (Rat and the root daemon use the same test).
public enum LocalNetwork {
    /// Loopback, private (10/8, 172.16/12, 192.168/16, fc00::/7), link-local (169.254/16, fe80::/10), and the user's
    /// own ranges.
    public static func contains(_ a: String, extra: LocalRanges = .shared) -> Bool {
        extra.contains(a) || a.hasPrefix("127.") || a.hasPrefix("10.") || a.hasPrefix("192.168.") || a.hasPrefix("169.254.") || a == "::1" ||
        a.hasPrefix("fe80:") || a.hasPrefix("fc") || a.hasPrefix("fd") || (a.hasPrefix("172.") && (16...31).contains(a.split(separator: ".").dropFirst().first.flatMap { Int($0) } ?? 0))
    }
}

/// Extra address ranges the user wants treated as the local network ("Additional IP Ranges in Local Network").
public final class LocalRanges: @unchecked Sendable {
    public static let shared = LocalRanges()
    private let lock = NSLock()
    public init() {}
    private var ranges: [(base: UInt32, mask: UInt32)] = []

    /// Parses "10.5.0.0/16, 100.64.0.0/10" (comma, space or newline separated). Returns the entries that did not parse.
    @discardableResult
    public func set(_ text: String) -> [String] {
        var bad: [String] = []
        var parsed: [(UInt32, UInt32)] = []
        for token in text.split(whereSeparator: { ", \n".contains($0) }) {
            if let r = Self.parse(String(token)) { parsed.append(r) } else { bad.append(String(token)) }
        }
        lock.withLock { ranges = parsed }
        return bad
    }

    public func contains(_ address: String) -> Bool {
        var a = in_addr()
        guard inet_pton(AF_INET, address, &a) == 1 else { return false }
        let ip = UInt32(bigEndian: a.s_addr)
        return lock.withLock { ranges.contains { (ip & $0.mask) == $0.base } }
    }

    public static func parse(_ s: String) -> (base: UInt32, mask: UInt32)? {
        let parts = s.split(separator: "/", omittingEmptySubsequences: false)
        guard parts.count <= 2 else { return nil }
        var a = in_addr()
        guard inet_pton(AF_INET, String(parts[0]), &a) == 1 else { return nil }
        let bits = parts.count == 2 ? Int(parts[1]) : 32
        guard let bits, (0...32).contains(bits) else { return nil }
        let mask: UInt32 = bits == 0 ? 0 : ~UInt32(0) << UInt32(32 - bits)
        return (UInt32(bigEndian: a.s_addr) & mask, mask)
    }
}
