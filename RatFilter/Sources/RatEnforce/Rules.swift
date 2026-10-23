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

public enum PFRules {
    /// The anchor's ruleset: only the local ports of sockets that belong to denied apps (or were denied by a rule).
    /// Nothing is ever blocked by remote address, because an address is shared by every app on the Mac (DNS
    /// resolvers, CDNs). Outgoing TCP gets an immediate RST and outgoing UDP an ICMP unreachable, so the app gives
    /// up at once; incoming packets are dropped. All rules are stateless (`no state`), so a connection that was
    /// already open is cut on its next packet, and there are no `pass` rules: nothing else is decided here.
    /// Loopback is never touched.
    public static func render(ports: [Int]) -> String {
        guard !ports.isEmpty else { return "" }
        let list = ports.sorted().map(String.init).joined(separator: " ")
        return """
        block return-rst out quick on ! lo0 proto tcp from any port { \(list) } to any no state
        block return-icmp out quick on ! lo0 proto udp from any port { \(list) } to any no state
        block drop in quick on ! lo0 proto { tcp udp } from any to any port { \(list) } no state

        """
    }

    /// Reads a list of ports, one per line; anything else is ignored.
    public static func parsePorts(_ text: String) -> [Int] {
        Set(text.split(whereSeparator: \.isNewline).compactMap { Int($0.trimmingCharacters(in: .whitespaces)) }.filter { (1...65535).contains($0) }).sorted()
    }
}
