import Foundation
import RatMonitor

/// The apps whose network access is denied, one executable or bundle path per line (written by Rat, read by the daemon).
public struct DeniedApps: Equatable {
    public private(set) var paths: [String]

    public init(text: String) {
        var out: [String] = []
        for p in text.split(whereSeparator: \.isNewline).map(String.init) where p.hasPrefix("/") && !p.contains("\0") {
            out.append(p)
            // "/Applications/Safari.app" is a symlink into the Safari cryptex; running processes report the real path.
            let real = (p as NSString).resolvingSymlinksInPath
            if real != p { out.append(real) }
            if let r = realpath(p, nil) {
                let s = String(cString: r); free(r)
                if s != p && s != real { out.append(s) }
            }
        }
        paths = out
    }

    public var isEmpty: Bool { paths.isEmpty }

    /// A process belongs to a denied app when its own path, or the path of the app it works for, is inside an entry.
    public func matches(path: String, responsiblePath: () -> String?) -> Bool {
        entry(for: path, responsiblePath: responsiblePath) != nil
    }

    /// The entry a process belongs to, if any.
    public func entry(for path: String, responsiblePath: () -> String?) -> String? {
        func inside(_ p: String) -> String? { paths.first { p == $0 || p.hasPrefix($0 + "/") } }
        if let e = inside(path) { return e }
        if ProcessGrouping.actsForOthers(path), let r = responsiblePath() { return inside(r) }
        return nil
    }
}

public enum PFRules {
    /// The anchor's ruleset: only the local ports of sockets that belong to denied apps (or were denied by a rule).
    /// Nothing is ever blocked by remote address, because an address is shared by every app on the Mac (DNS
    /// resolvers, CDNs). Outgoing TCP gets an immediate RST and outgoing UDP an ICMP unreachable, so the app gives
    /// up at once; incoming packets are dropped. All rules are stateless (`no state`), so a connection that was
    /// already open is cut on its next packet, and there are no `pass` rules: nothing else is decided here.
    ///
    /// `loopbackPorts` are the local ports of loopback TCP connections a denied app made to another program (a local
    /// proxy or SSH forward, which would otherwise carry its traffic off the Mac). On lo0 each such port belongs to
    /// one connection only; the client gets an RST and the proxy's answers are dropped. Nothing else on lo0 is touched.
    public static func render(ports: [Int], loopbackPorts: [Int] = []) -> String {
        var out = ""
        if !ports.isEmpty {
            let list = ports.sorted().map(String.init).joined(separator: " ")
            out += """
            block return-rst out quick on ! lo0 proto tcp from any port { \(list) } to any no state
            block return-icmp out quick on ! lo0 proto udp from any port { \(list) } to any no state
            block drop in quick on ! lo0 proto { tcp udp } from any to any port { \(list) } no state

            """
        }
        if !loopbackPorts.isEmpty {
            let list = loopbackPorts.sorted().map(String.init).joined(separator: " ")
            out += """
            block return-rst out quick on lo0 proto tcp from any port { \(list) } to any no state
            block drop in quick on lo0 proto tcp from any to any port { \(list) } no state

            """
        }
        return out
    }

    /// Reads a list of ports, one per line; anything else is ignored.
    public static func parsePorts(_ text: String) -> [Int] {
        Set(text.split(whereSeparator: \.isNewline).compactMap { Int($0.trimmingCharacters(in: .whitespaces)) }.filter { (1...65535).contains($0) }).sorted()
    }

    /// Loopback ports in the same file, written as `lo0 <port>` (Rat: a rule denies where a proxied connection goes).
    public static func parseLoopbackPorts(_ text: String) -> [Int] {
        Set(text.split(whereSeparator: \.isNewline).compactMap { line -> Int? in
            let t = line.split(separator: " ", omittingEmptySubsequences: true)
            guard t.count == 2, t[0] == "lo0", let p = Int(t[1]), (1...65535).contains(p) else { return nil }
            return p
        }).sorted()
    }
}
