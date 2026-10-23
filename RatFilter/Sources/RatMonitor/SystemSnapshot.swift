import Foundation

/// Parses the root helper's `lsof -F pPnT` + `ps` snapshot into connections for every process,
/// including ones an unprivileged app cannot inspect.
public enum SystemSnapshot {
    public static func parse(_ text: String) -> [ObservedConnection] {
        var paths: [Int32: String] = [:]
        var lsofLines: [Substring] = []
        var inPS = false
        for line in text.split(separator: "\n", omittingEmptySubsequences: true) {
            if line == "#PS" { inPS = true; continue }
            if inPS {
                let t = line.drop(while: { $0 == " " })
                guard let sp = t.firstIndex(of: " "), let pid = Int32(t[..<sp]) else { continue }
                paths[pid] = String(t[t.index(after: sp)...].drop(while: { $0 == " " }))
            } else { lsofLines.append(line) }
        }

        var out: [ObservedConnection] = []
        var pid: Int32 = 0
        var proto: ObservedConnection.Proto = .tcp
        var name: String?
        var state: String?

        func flush() {
            defer { name = nil; state = nil }
            guard let name, let arrow = name.range(of: "->") else { return }
            guard let l = splitEndpoint(String(name[..<arrow.lowerBound])), let r = splitEndpoint(String(name[arrow.upperBound...])) else { return }
            out.append(ObservedConnection(pid: pid, processPath: paths[pid] ?? "pid \(pid)", proto: proto,
                                          remoteAddress: r.host, remotePort: r.port, localPort: l.port, tcpState: proto == .tcp ? state : nil,
                                          localAddress: l.host))
        }

        for line in lsofLines {
            guard let tag = line.first else { continue }
            let value = line.dropFirst()
            switch tag {
            case "p": flush(); pid = Int32(value) ?? 0; proto = .tcp
            case "f": flush()
            case "P": proto = value == "UDP" ? .udp : .tcp
            case "n": name = String(value)
            case "T": if value.hasPrefix("ST=") { state = String(value.dropFirst(3)) }
            default: break
            }
        }
        flush()
        return out
    }

    /// "1.2.3.4:443" or "[fe80::1]:443" → host, port.
    static func splitEndpoint(_ s: String) -> (host: String, port: Int)? {
        guard let colon = s.lastIndex(of: ":"), let port = Int(s[s.index(after: colon)...]) else { return nil }
        var host = String(s[..<colon])
        if host.hasPrefix("["), host.hasSuffix("]") { host = String(host.dropFirst().dropLast()) }
        return (host, port)
    }
}
