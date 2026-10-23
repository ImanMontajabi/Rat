import Foundation
import RatMonitor

/// The apps whose network access is denied, one executable or bundle path per line (written by Rat, read by the daemon).
public struct DeniedApps: Equatable {
    public private(set) var paths: [String]

    public init(text: String) {
        paths = text.split(whereSeparator: \.isNewline).map(String.init).filter { $0.hasPrefix("/") && !$0.contains("\0") }
    }

    public var isEmpty: Bool { paths.isEmpty }

    /// A process belongs to a denied app when its own path, or the path of the app it works for, is inside an entry.
    public func matches(path: String, responsiblePath: () -> String?) -> Bool {
        func inside(_ p: String) -> Bool { paths.contains { p == $0 || p.hasPrefix($0 + "/") } }
        if inside(path) { return true }
        if ProcessGrouping.actsForOthers(path), let r = responsiblePath() { return inside(r) }
        return false
    }
}

public enum Address {
    /// Whether an address is worth putting in a firewall table: public unicast only. LAN, loopback, link-local and
    /// multicast addresses (router, DNS, mDNS) are never blocked by address.
    public static func isPublic(_ a: String) -> Bool {
        var v4 = in_addr()
        if inet_pton(AF_INET, a, &v4) == 1 {
            let ip = UInt32(bigEndian: v4.s_addr)
            let o1 = ip >> 24, o2 = (ip >> 16) & 0xff
            if o1 == 0 || o1 == 10 || o1 == 127 || o1 >= 224 { return false }
            if o1 == 169 && o2 == 254 { return false }
            if o1 == 172 && (16...31).contains(o2) { return false }
            if o1 == 192 && o2 == 168 { return false }
            if o1 == 100 && (64...127).contains(o2) { return false }
            return true
        }
        var v6 = in6_addr()
        guard inet_pton(AF_INET6, a, &v6) == 1 else { return false }
        let b = withUnsafeBytes(of: &v6) { Array($0) }
        if b.allSatisfy({ $0 == 0 }) { return false }
        if b[0] == 0xff || (b[0] == 0xfe && (b[1] & 0xc0) == 0x80) || (b[0] & 0xfe) == 0xfc { return false }
        if b.dropLast().allSatisfy({ $0 == 0 }) && b[15] == 1 { return false }
        return true
    }
}

public enum PFRules {
    /// The anchor's ruleset. Blocks by address (rules that deny a server for everyone) and by local port (every
    /// socket of a denied app). Outgoing TCP gets an immediate RST and outgoing UDP an ICMP unreachable, so the
    /// app gives up at once instead of retransmitting; incoming packets are dropped. Loopback is never touched.
    public static func render(ports: [Int], addresses: [String]) -> String {
        var out = "table <rat_blocked> persist {\(addresses.sorted().joined(separator: " "))}\n"
        out += "block drop out quick from any to <rat_blocked> no state\n"
        out += "block drop in quick from <rat_blocked> to any no state\n"
        let list = ports.sorted().map(String.init).joined(separator: " ")
        if !ports.isEmpty {
            out += "block return-rst out quick on ! lo0 proto tcp from any port { \(list) } to any\n"
            out += "block return-icmp out quick on ! lo0 proto udp from any port { \(list) } to any\n"
            out += "block drop in quick on ! lo0 proto { tcp udp } from any to any port { \(list) }\n"
        }
        return out
    }

    /// Reads the address blocklist Rat writes (one IP per line), keeping only valid public addresses.
    public static func parseBlocklist(_ text: String, limit: Int = 5000) -> [String] {
        var seen = Set<String>()
        var out: [String] = []
        for line in text.split(whereSeparator: \.isNewline) {
            let a = line.trimmingCharacters(in: .whitespaces)
            var v4 = in_addr(), v6 = in6_addr()
            guard inet_pton(AF_INET, a, &v4) == 1 || inet_pton(AF_INET6, a, &v6) == 1, seen.insert(a).inserted else { continue }
            out.append(a)
            if out.count >= limit { break }
        }
        return out
    }
}
