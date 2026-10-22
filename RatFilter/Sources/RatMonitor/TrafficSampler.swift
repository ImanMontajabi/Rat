import Foundation
import os

private let logger = Logger(subsystem: "com.imanmontajabi.Rat", category: "traffic")

/// Cumulative byte counters for one process, as reported by `nettop`.
public struct TrafficCounter: Equatable, Sendable {
    public var pid: Int32
    public var name: String
    public var bytesIn: UInt64
    public var bytesOut: UInt64
}

/// Per-process traffic via the system `nettop` tool (no entitlements needed).
public enum TrafficSampler {
    /// Parses `nettop -P -L 1 -J bytes_in,bytes_out` CSV: `name.pid,bytes_in,bytes_out,`
    public static func parse(_ csv: String) -> [TrafficCounter] {
        csv.split(whereSeparator: \.isNewline).compactMap { line in
            let f = line.split(separator: ",", omittingEmptySubsequences: false)
            guard f.count >= 3, let inB = UInt64(f[1]), let outB = UInt64(f[2]),
                  let dot = f[0].lastIndex(of: "."), let pid = Int32(f[0][f[0].index(after: dot)...]) else { return nil }
            return TrafficCounter(pid: pid, name: String(f[0][..<dot]), bytesIn: inB, bytesOut: outB)
        }
    }

    public static func sample() -> [TrafficCounter] {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/nettop")
        p.arguments = ["-P", "-L", "1", "-J", "bytes_in,bytes_out"]
        let pipe = Pipe()
        p.standardOutput = pipe
        p.standardError = FileHandle.nullDevice
        do { try p.run() } catch {
            logger.error("nettop failed to start: \(error.localizedDescription, privacy: .public)")
            return []
        }
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        p.waitUntilExit()
        let rows = parse(String(decoding: data, as: UTF8.self))
        logger.notice("nettop returned \(rows.count, privacy: .public) processes")
        return rows
    }
}
