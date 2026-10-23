import Darwin
import Foundation
import os

private let logger = Logger(subsystem: "com.imanmontajabi.Rat", category: "sampler")

/// One observed socket belonging to a process.
public struct ObservedConnection: Hashable, Sendable {
    public enum Proto: String, Sendable { case tcp, udp }

    public var pid: Int32
    public var processPath: String
    public var proto: Proto
    public var remoteAddress: String   // empty for unconnected UDP / listeners
    public var remotePort: Int
    public var localPort: Int
    public var tcpState: String?

    public var processName: String { (processPath as NSString).lastPathComponent }
    public var isOutbound: Bool { !remoteAddress.isEmpty && remotePort != 0 }
}

/// Entitlement-free connection discovery via libproc. Processes owned by other users
/// are invisible unless the caller is root.
public enum ConnectionSampler {
    public static func sample() -> [ObservedConnection] {
        var result: [ObservedConnection] = []
        for pid in allPIDs() { result.append(contentsOf: connections(of: pid)) }
        logger.notice("sampled \(result.count, privacy: .public) sockets")
        return result
    }

    public static func allPIDs() -> [pid_t] {
        let bytes = proc_listallpids(nil, 0)
        guard bytes > 0 else { return [] }
        var pids = [pid_t](repeating: 0, count: Int(bytes) + 64)
        let n = proc_listallpids(&pids, Int32(pids.count * MemoryLayout<pid_t>.stride))
        return n > 0 ? Array(pids.prefix(Int(n))).filter { $0 > 0 } : []
    }

    public static func path(of pid: pid_t) -> String {
        var buf = [CChar](repeating: 0, count: 4 * Int(MAXPATHLEN))
        return proc_pidpath(pid, &buf, UInt32(buf.count)) > 0 ? String(cString: buf) : "pid \(pid)"
    }

    /// Socket descriptors of a process (empty if it cannot be inspected).
    public static func socketFDs(of pid: pid_t) -> [Int32] {
        let listBytes = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, nil, 0)
        guard listBytes > 0 else { return [] }
        var fds = [proc_fdinfo](repeating: proc_fdinfo(), count: Int(listBytes) / MemoryLayout<proc_fdinfo>.stride + 8)
        let got = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, &fds, Int32(fds.count * MemoryLayout<proc_fdinfo>.stride))
        guard got > 0 else { return [] }
        return fds.prefix(Int(got) / MemoryLayout<proc_fdinfo>.stride).filter { $0.proc_fdtype == UInt32(PROX_FDTYPE_SOCKET) }.map(\.proc_fd)
    }

    public static func connections(of pid: pid_t) -> [ObservedConnection] {
        let path = path(of: pid)
        return socketFDs(of: pid).compactMap { connection(pid: pid, fd: $0, processPath: path) }
    }

    /// One TCP or UDP socket, or nil for other kinds.
    public static func connection(pid: pid_t, fd: Int32, processPath: String) -> ObservedConnection? {
        var info = socket_fdinfo()
        let r = proc_pidfdinfo(pid, fd, PROC_PIDFDSOCKETINFO, &info, Int32(MemoryLayout<socket_fdinfo>.size))
        guard r == Int32(MemoryLayout<socket_fdinfo>.size) else { return nil }
        let proto: ObservedConnection.Proto
        let ini: in_sockinfo
        var state: String?
        switch Int(info.psi.soi_kind) {
        case SOCKINFO_TCP:
            proto = .tcp
            ini = info.psi.soi_proto.pri_tcp.tcpsi_ini
            state = tcpStateName(info.psi.soi_proto.pri_tcp.tcpsi_state)
        case SOCKINFO_IN where info.psi.soi_protocol == IPPROTO_UDP:
            proto = .udp
            ini = info.psi.soi_proto.pri_in
        default:
            return nil
        }
        return ObservedConnection(pid: pid, processPath: processPath, proto: proto,
                                  remoteAddress: foreignAddress(ini), remotePort: Int(UInt16(truncatingIfNeeded: ini.insi_fport).bigEndian),
                                  localPort: Int(UInt16(truncatingIfNeeded: ini.insi_lport).bigEndian), tcpState: state)
    }

    private static func foreignAddress(_ ini: in_sockinfo) -> String {
        var buf = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
        if Int32(ini.insi_vflag) & INI_IPV4 != 0 {
            var a = ini.insi_faddr.ina_46.i46a_addr4
            guard a.s_addr != 0 else { return "" }
            return inet_ntop(AF_INET, &a, &buf, socklen_t(buf.count)).map { String(cString: $0) } ?? ""
        }
        if Int32(ini.insi_vflag) & INI_IPV6 != 0 {
            var a = ini.insi_faddr.ina_6
            let isAny = withUnsafeBytes(of: &a) { $0.allSatisfy { $0 == 0 } }
            guard !isAny else { return "" }
            return inet_ntop(AF_INET6, &a, &buf, socklen_t(buf.count)).map { String(cString: $0) } ?? ""
        }
        return ""
    }

    private static func tcpStateName(_ s: Int32) -> String {
        switch s {
        case 0: return "CLOSED"
        case 1: return "LISTEN"
        case 2: return "SYN_SENT"
        case 3: return "SYN_RECEIVED"
        case 4: return "ESTABLISHED"
        case 5: return "CLOSE_WAIT"
        case 6: return "FIN_WAIT_1"
        case 7: return "CLOSING"
        case 8: return "LAST_ACK"
        case 9: return "FIN_WAIT_2"
        case 10: return "TIME_WAIT"
        default: return "UNKNOWN(\(s))"
        }
    }
}
