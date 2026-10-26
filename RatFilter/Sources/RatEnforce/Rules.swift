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
        if let app = ProcessGrouping.companionApp(of: path), let e = inside(app) { return e }
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

    /// Whether the anchor's rules as `pfctl -a <anchor> -s rules` prints them still block every port: `ports` off
    /// lo0 and `loopback` on lo0. pfctl expands a list into one rule per port (`from any port = 50200`).
    public static func holds(_ text: String, ports: [Int], loopback: [Int]) -> Bool {
        var outside = Set<Int>(), onLoopback = Set<Int>()
        for line in text.split(whereSeparator: \.isNewline) where line.hasPrefix("block ") {
            let t = line.split(separator: " ", omittingEmptySubsequences: true)
            var found: [Int] = []
            var i = 0
            while i + 1 < t.count {
                defer { i += 1 }
                guard t[i] == "port" else { continue }
                if t[i + 1] == "=", i + 2 < t.count, let p = Int(t[i + 2]) { found.append(p) }
                if t[i + 1] == "{" { found += t[(i + 2)...].prefix { $0 != "}" }.compactMap { Int($0) } }
            }
            if line.contains(" on lo0 ") { onLoopback.formUnion(found) } else { outside.formUnion(found) }
        }
        return Set(ports).isSubset(of: outside) && Set(loopback).isSubset(of: onLoopback)
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
