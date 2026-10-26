import Foundation
import os

private let logger = Logger(subsystem: "com.imanmontajabi.Rat", category: "traffic")

/// Cumulative byte counters for one process, as reported by `nettop`.
public struct TrafficCounter: Equatable, Sendable {
    public var pid: Int32
    public var name: String
    public var bytesIn: UInt64
    public var bytesOut: UInt64

    public init(pid: Int32, name: String, bytesIn: UInt64, bytesOut: UInt64) {
        self.pid = pid; self.name = name; self.bytesIn = bytesIn; self.bytesOut = bytesOut
    }
}

/// Cumulative byte counters for one connection (a flow) of a process, as reported by `nettop`.
public struct FlowCounter: Equatable, Sendable {
    public var pid: Int32
    public var proto: ObservedConnection.Proto
    public var localPort: Int
    public var remoteAddress: String
    public var remotePort: Int
    public var bytesIn: UInt64
    public var bytesOut: UInt64

    public init(pid: Int32, proto: ObservedConnection.Proto, localPort: Int, remoteAddress: String, remotePort: Int, bytesIn: UInt64, bytesOut: UInt64) {
        self.pid = pid; self.proto = proto; self.localPort = localPort; self.remoteAddress = remoteAddress; self.remotePort = remotePort
        self.bytesIn = bytesIn; self.bytesOut = bytesOut
    }

    /// Matches the socket from `ConnectionSampler`: a process's local port and the server's port name one connection
    /// without comparing address spellings (nettop writes `2a00::1.443`, libproc `2a00::1` and 443 apart).
    public var key: String { Self.key(pid: pid, proto: proto, localPort: localPort, remotePort: remotePort) }
    public static func key(pid: Int32, proto: ObservedConnection.Proto, localPort: Int, remotePort: Int) -> String {
        "\(pid)|\(proto.rawValue)|\(localPort)|\(remotePort)"
    }
}

/// Per-process and per-connection traffic via the system `nettop` tool (no entitlements needed).
public enum TrafficSampler {
    public struct Sample: Sendable {
        public var processes: [TrafficCounter] = []
        public var flows: [FlowCounter] = []
        public init(processes: [TrafficCounter] = [], flows: [FlowCounter] = []) { self.processes = processes; self.flows = flows }
    }

    /// Parses `nettop -P -L 1 -J bytes_in,bytes_out` CSV: `name.pid,bytes_in,bytes_out,`
    public static func parse(_ csv: String) -> [TrafficCounter] { parseSample(csv).processes }

    /// Parses `nettop -L 1 -n -J bytes_in,bytes_out` CSV: each process line (`name.pid,in,out,`) is followed by its
    /// connections (`tcp4 192.0.2.1:50576<->17.57.146.22:5223,in,out,`; IPv6 writes the port after a dot).
    public static func parseSample(_ csv: String) -> Sample {
        var out = Sample()
        var current: Int32?
        for line in csv.split(whereSeparator: \.isNewline) {
            let f = line.split(separator: ",", omittingEmptySubsequences: false)
            guard f.count >= 3 else { continue }
            let head = f[0]
            if let space = head.firstIndex(of: " "), ["tcp4", "tcp6", "udp4", "udp6"].contains(head[..<space]) {
                guard let pid = current, let flow = flow(head, pid: pid, bytesIn: f[1], bytesOut: f[2]) else { continue }
                out.flows.append(flow)
                continue
            }
            guard let inB = UInt64(f[1]), let outB = UInt64(f[2]),
                  let dot = head.lastIndex(of: "."), let pid = Int32(head[head.index(after: dot)...]) else { current = nil; continue }
            current = pid
            out.processes.append(TrafficCounter(pid: pid, name: String(head[..<dot]), bytesIn: inB, bytesOut: outB))
        }
        return out
    }

    private static func flow(_ head: Substring, pid: Int32, bytesIn: Substring, bytesOut: Substring) -> FlowCounter? {
        let kind = head.prefix(4)
        let v6 = kind.hasSuffix("6")
        let ends = head.dropFirst(5).components(separatedBy: "<->")
        guard ends.count == 2, let inB = UInt64(bytesIn), let outB = UInt64(bytesOut) else { return nil }
        func split(_ s: String) -> (String, Int)? {
            guard let i = s.lastIndex(of: v6 ? "." : ":"), let port = Int(s[s.index(after: i)...]) else { return nil }
            return (String(s[..<i]), port)
        }
        guard let local = split(ends[0]), let remote = split(ends[1]), remote.1 != 0 else { return nil }
        return FlowCounter(pid: pid, proto: kind.hasPrefix("tcp") ? .tcp : .udp, localPort: local.1, remoteAddress: remote.0, remotePort: remote.1,
                           bytesIn: inB, bytesOut: outB)
    }

    public static func sample() -> [TrafficCounter] { run(["-P", "-L", "1", "-J", "bytes_in,bytes_out"]).processes }

    /// Processes and their connections in one run. `-n`: addresses stay numeric (no lookups).
    public static func sampleWithFlows() -> Sample { run(["-L", "1", "-n", "-J", "bytes_in,bytes_out"]) }

    private static func run(_ arguments: [String]) -> Sample {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/nettop")
        p.arguments = arguments
        let pipe = Pipe()
        p.standardOutput = pipe
        p.standardError = FileHandle.nullDevice
        do { try p.run() } catch {
            logger.error("nettop failed to start: \(error.localizedDescription, privacy: .public)")
            return Sample()
        }
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        p.waitUntilExit()
        let rows = parseSample(String(decoding: data, as: UTF8.self))
        logger.notice("nettop returned \(rows.processes.count, privacy: .public) processes, \(rows.flows.count, privacy: .public) connections")
        return rows
    }
}
