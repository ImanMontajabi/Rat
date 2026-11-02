import Darwin
import Foundation

/// The bytes one network interface moved since it came up (the kernel's 64-bit counters).
public struct InterfaceCounter: Equatable, Sendable {
    public var name: String
    public var bytesIn: UInt64
    public var bytesOut: UInt64
    public init(name: String, bytesIn: UInt64, bytesOut: UInt64) { self.name = name; self.bytesIn = bytesIn; self.bytesOut = bytesOut }
}

/// The Mac's Internet traffic, counted on the interfaces that lead to the Internet rather than summed over processes.
///
/// A process's counters (`nettop`) count every socket it holds, so a sum over processes counts a byte more than once:
/// loopback traffic twice (the sender's and the receiver's socket), a byte through a local proxy on the app's loopback
/// socket and on the proxy's outside one, and a byte through a VPN on the app's socket in the tunnel and again on the
/// VPN client's socket that carries the tunnel. A physical interface sees each byte once (as Activity Monitor and
/// Stats count it). The rows of apps, processes and connections keep their own counters.
public struct InternetTraffic: Sendable {
    /// Every interface's counters from the last sample (all of them, so an interface that starts leading to the
    /// Internet, such as Ethernet plugged in, counts from its next sample on).
    private var last: [String: (bytesIn: UInt64, bytesOut: UInt64)] = [:]

    public init() {}

    /// The bytes the `internet` interfaces moved since the last sample. Nothing on the first sample, and nothing for
    /// an interface whose counters went back (it was recreated: a USB adapter plugged in again).
    public mutating func update(_ counters: [InterfaceCounter], internet: Set<String>) -> (bytesIn: UInt64, bytesOut: UInt64) {
        var bytesIn: UInt64 = 0, bytesOut: UInt64 = 0
        var now: [String: (bytesIn: UInt64, bytesOut: UInt64)] = [:]
        for c in counters {
            now[c.name] = (c.bytesIn, c.bytesOut)
            guard internet.contains(c.name), let before = last[c.name], c.bytesIn >= before.bytesIn, c.bytesOut >= before.bytesOut else { continue }
            bytesIn += c.bytesIn - before.bytesIn; bytesOut += c.bytesOut - before.bytesOut
        }
        last = now
        return (bytesIn, bytesOut)
    }

    /// The interfaces that lead to the Internet: those the routing table holds a default route on (scoped or not),
    /// other than loopback and tunnels. The tunnel's own packets leave through the interface under it, so counting the
    /// tunnel too would count a VPN's traffic twice. A PPP interface counts only when nothing else has a default route
    /// (PPPoE: the line itself is PPP; an L2TP VPN runs over Wi-Fi or Ethernet).
    public static func internetInterfaces(defaultRoutes: Set<String>) -> Set<String> {
        let candidates = defaultRoutes.filter { !$0.hasPrefix("lo") }
        let physical = candidates.filter { !NetworkRoutes.isTunnel($0) }
        return physical.isEmpty ? candidates.filter { $0.hasPrefix("ppp") && NetworkRoutes.isTunnel($0) } : physical
    }

    /// Reads every interface's counters (`sysctl` `NET_RT_IFLIST2`: `if_data64`, so they do not wrap at 4 GB; no root needed).
    public static func counters() -> [InterfaceCounter] {
        var mib: [Int32] = [CTL_NET, PF_ROUTE, 0, 0, NET_RT_IFLIST2, 0]
        var size = 0
        guard sysctl(&mib, 6, nil, &size, nil, 0) == 0, size > 0 else { return [] }
        size += size / 4   // room for an interface added in between
        var buf = [UInt8](repeating: 0, count: size)
        guard sysctl(&mib, 6, &buf, &size, nil, 0) == 0 else { return [] }
        let header = MemoryLayout<if_msghdr>.size, header2 = MemoryLayout<if_msghdr2>.size
        var out: [InterfaceCounter] = []
        var at = 0
        while at + header <= size {
            let m = buf.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: at, as: if_msghdr.self) }
            let length = Int(m.ifm_msglen)
            guard length >= 4, at + length <= size else { break }
            defer { at += length }
            guard m.ifm_type == UInt8(RTM_IFINFO2), length >= header2 else { continue }
            let m2 = buf.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: at, as: if_msghdr2.self) }
            var name = [CChar](repeating: 0, count: Int(IF_NAMESIZE))
            guard if_indextoname(UInt32(m2.ifm_index), &name) != nil else { continue }
            out.append(InterfaceCounter(name: String(cString: name), bytesIn: m2.ifm_data.ifi_ibytes, bytesOut: m2.ifm_data.ifi_obytes))
        }
        return out
    }

    /// The interfaces the routing table holds a default route on (`0.0.0.0/0` or `::/0`, scoped or not; a VPN's
    /// `0/1` and `128.0/1` are not defaults). `sysctl` `NET_RT_DUMP`, no root needed.
    public static func defaultRouteInterfaces() -> Set<String> {
        var mib: [Int32] = [CTL_NET, PF_ROUTE, 0, AF_UNSPEC, NET_RT_DUMP, 0]
        var size = 0
        guard sysctl(&mib, 6, nil, &size, nil, 0) == 0, size > 0 else { return [] }
        size += size / 4
        var buf = [UInt8](repeating: 0, count: size)
        guard sysctl(&mib, 6, &buf, &size, nil, 0) == 0 else { return [] }
        var out = Set<String>()
        for index in defaultRouteIndices(in: Array(buf.prefix(size))) {
            var name = [CChar](repeating: 0, count: Int(IF_NAMESIZE))
            if if_indextoname(UInt32(index), &name) != nil { out.insert(String(cString: name)) }
        }
        return out
    }

    /// The interface indices of the default routes in a `NET_RT_DUMP` buffer: up gateway routes, not to a host, whose
    /// destination is the unspecified address and whose netmask is all zeros (absent bytes are zeros).
    static func defaultRouteIndices(in buf: [UInt8]) -> Set<UInt16> {
        let header = MemoryLayout<rt_msghdr>.size
        func roundup(_ n: Int) -> Int { n > 0 ? 1 + ((n - 1) | (MemoryLayout<UInt32>.size - 1)) : MemoryLayout<UInt32>.size }
        var out = Set<UInt16>()
        var at = 0
        while at + header <= buf.count {
            let m = buf.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: at, as: rt_msghdr.self) }
            let length = Int(m.rtm_msglen)
            guard length >= header, at + length <= buf.count else { break }
            defer { at += length }
            guard m.rtm_version == UInt8(RTM_VERSION), m.rtm_flags & (RTF_UP | RTF_GATEWAY) == RTF_UP | RTF_GATEWAY, m.rtm_flags & RTF_HOST == 0,
                  m.rtm_addrs & RTA_DST != 0, m.rtm_addrs & RTA_NETMASK != 0 else { continue }
            // The addresses follow the header in RTA_* bit order, each rounded up to 4 bytes.
            var sockaddrs: [Int: Range<Int>] = [:]
            var p = at + header
            let end = at + length
            for bit in 0..<Int(RTAX_MAX) where m.rtm_addrs & (1 << bit) != 0 {
                guard p < end else { break }
                let len = Int(buf[p])
                sockaddrs[bit] = p..<min(p + len, end)
                p += roundup(len)
            }
            guard let dst = sockaddrs[Int(RTAX_DST)], dst.count >= 2, let mask = sockaddrs[Int(RTAX_NETMASK)] else { continue }
            let family = Int32(buf[dst.lowerBound + 1])
            let addressBytes: Range<Int>
            switch family {
            case AF_INET: addressBytes = 4..<8
            case AF_INET6: addressBytes = 8..<24
            default: continue
            }
            func zero(_ r: Range<Int>, _ bytes: Range<Int>) -> Bool {
                bytes.allSatisfy { r.lowerBound + $0 >= r.upperBound || buf[r.lowerBound + $0] == 0 }
            }
            // A netmask's own family byte is often left 0, so its address part is read at the destination's offsets.
            guard zero(dst, addressBytes), zero(mask, addressBytes) else { continue }
            out.insert(m.rtm_index)
        }
        return out
    }
}
