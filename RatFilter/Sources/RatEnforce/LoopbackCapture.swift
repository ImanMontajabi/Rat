import Darwin
import Foundation

/// One TCP segment seen on lo0 (BPF link type DLT_NULL: a 4-byte address family in host byte order, then IP).
public struct LoopbackSegment: Equatable {
    public var sourcePort: Int
    public var destinationPort: Int
    public var ipv6: Bool
    public var payload: [UInt8]

    /// Parses a captured frame; nil for anything but TCP over IPv4/IPv6 (no IPv6 extension headers).
    public static func parse(_ f: [UInt8]) -> LoopbackSegment? {
        guard f.count >= 4 else { return nil }
        let family = Int(f[0]) | Int(f[1]) << 8 | Int(f[2]) << 16 | Int(f[3]) << 24
        let ip = 4, tcp: Int, v6: Bool
        switch Int32(family) {
        case AF_INET:
            guard f.count >= ip + 20, f[ip] >> 4 == 4, f[ip + 9] == 6 else { return nil }
            // Fragments other than the first carry no TCP header.
            guard (Int(f[ip + 6]) & 0x1f) << 8 | Int(f[ip + 7]) == 0 else { return nil }
            tcp = ip + Int(f[ip] & 0x0f) * 4
            v6 = false
        case AF_INET6:
            guard f.count >= ip + 40, f[ip] >> 4 == 6, f[ip + 6] == 6 else { return nil }
            tcp = ip + 40
            v6 = true
        default:
            return nil
        }
        guard f.count >= tcp + 20 else { return nil }
        let data = tcp + Int(f[tcp + 12] >> 4) * 4
        guard data >= tcp + 20, data <= f.count else { return nil }
        return LoopbackSegment(sourcePort: Int(f[tcp]) << 8 | Int(f[tcp + 1]), destinationPort: Int(f[tcp + 2]) << 8 | Int(f[tcp + 3]),
                               ipv6: v6, payload: Array(f[data...]))
    }
}

/// A classic BPF program, assembled here because the kernel only takes raw instructions.
public struct BPFInstruction: Equatable {
    public var code: UInt16, jt: UInt8, jf: UInt8, k: UInt32
}

public enum LoopbackFilter {
    // Opcodes from <net/bpf.h>.
    static let ldW: UInt16 = 0x00 | 0x00 | 0x20, ldH: UInt16 = 0x00 | 0x08 | 0x20, ldB: UInt16 = 0x00 | 0x10 | 0x20
    static let ldWInd: UInt16 = 0x00 | 0x00 | 0x40, ldBInd: UInt16 = 0x00 | 0x10 | 0x40
    static let ldxMSH: UInt16 = 0x01 | 0x10 | 0xa0
    static let andK: UInt16 = 0x04 | 0x50, rshK: UInt16 = 0x04 | 0x70, addX: UInt16 = 0x04 | 0x00 | 0x08
    static let jeqK: UInt16 = 0x05 | 0x10, jsetK: UInt16 = 0x05 | 0x40, ja: UInt16 = 0x05
    static let tax: UInt16 = 0x07, st: UInt16 = 0x02, ldMem: UInt16 = 0x00 | 0x60, retK: UInt16 = 0x06

    /// The first payload words of requests a proxy receives: HTTP methods and the SOCKS5/SOCKS4 CONNECT requests.
    static let httpWords: [UInt32] = ["CONN", "GET ", "POST", "PUT ", "HEAD", "DELE", "OPTI", "PATC"].map { s in
        s.utf8.reduce(0) { $0 << 8 | UInt32($1) }
    }

    /// Accepts only TCP segments on lo0 whose payload starts like a proxy request, so the kernel hands the daemon
    /// a handful of packets per connection instead of the whole loopback traffic (a proxied download, a database).
    /// Accepted packets are cut to `snap` bytes: only the request line or SOCKS request is ever read.
    public static func program(snap: UInt32 = 600) -> [BPFInstruction] {
        enum Op { case i(UInt16, UInt32), jump(UInt16, UInt32, String?, String?), label(String) }
        let accept = "accept", reject = "reject"
        var ops: [Op] = [
            .i(ldB, 0),                                  // address family, low byte (host byte order)
            .jump(jeqK, UInt32(AF_INET), "v4", nil),
            .jump(jeqK, UInt32(AF_INET6), "v6", reject),
            .label("v4"),
            .i(ldB, 4 + 9), .jump(jeqK, 6, nil, reject), // TCP
            .i(ldH, 4 + 6), .jump(jsetK, 0x1fff, reject, nil),   // not a later fragment
            .i(ldxMSH, 4),                               // X = IP header length
            .i(ldBInd, 4 + 12),                          // TCP data offset byte
            .i(andK, 0xf0), .i(rshK, 2), .i(addX, 0), .i(tax, 0),   // X = IP + TCP header length
            .i(ldWInd, 4),                               // first payload word
            .jump(ja, 0, "check", nil),
            .label("v6"),
            .i(ldB, 4 + 6), .jump(jeqK, 6, nil, reject), // next header TCP
            .i(ldB, 4 + 40 + 12), .i(andK, 0xf0), .i(rshK, 2), .i(tax, 0),
            .i(ldWInd, 4 + 40),
            .label("check"),
        ]
        for w in httpWords { ops.append(.jump(jeqK, w, accept, nil)) }
        ops += [
            .i(st, 0),
            .i(andK, 0xffff_ff00), .jump(jeqK, 0x0501_0000, accept, nil),   // SOCKS5: VER 5, CONNECT, RSV 0
            .i(ldMem, 0), .i(rshK, 16), .jump(jeqK, 0x0401, accept, reject), // SOCKS4: VN 4, CONNECT
            .label(accept), .i(retK, snap),
            .label(reject), .i(retK, 0),
        ]
        // Two passes: label addresses, then relative jump offsets.
        var at: [String: Int] = [:], n = 0
        for op in ops { if case .label(let l) = op { at[l] = n } else { n += 1 } }
        var out: [BPFInstruction] = [], pc = 0
        for op in ops {
            switch op {
            case .label: continue
            case .i(let code, let k): out.append(BPFInstruction(code: code, jt: 0, jf: 0, k: k))
            case .jump(let code, let k, let t, let f):
                func off(_ l: String?) -> UInt8 { l.map { UInt8(at[$0]! - pc - 1) } ?? 0 }
                if code == ja { out.append(BPFInstruction(code: code, jt: 0, jf: 0, k: UInt32(at[t!]! - pc - 1))) }
                else { out.append(BPFInstruction(code: code, jt: off(t), jf: off(f), k: k)) }
            }
            pc += 1
        }
        return out
    }
}

/// Reads lo0 through a BPF device (root only). Packets arrive filtered by `LoopbackFilter`.
public final class LoopbackCapture {
    private let fd: Int32
    private var buffer: [UInt8]

    // ioctl numbers from <net/bpf.h> (_IOW/_IOWR are macros Swift does not import).
    private static func iow(_ n: UInt, _ size: Int, read: Bool = false) -> UInt {
        (read ? 0xC000_0000 : 0x8000_0000) | (UInt(size & 0x1fff) << 16) | (UInt(UInt8(ascii: "B")) << 8) | n
    }

    /// Opens a free /dev/bpf device on lo0; nil when none is available or this is not root.
    public init?(interface: String = "lo0", bufferSize: UInt32 = 512 * 1024, readTimeout: TimeInterval = 1) {
        var opened: Int32 = -1
        for i in 0..<256 {
            let f = open("/dev/bpf\(i)", O_RDONLY)
            if f >= 0 { opened = f; break }
            if errno != EBUSY { break }
        }
        guard opened >= 0 else { return nil }
        let f = opened
        var blen = bufferSize
        var one: UInt32 = 1
        var ifr = [UInt8](repeating: 0, count: 32)
        for (i, c) in interface.utf8.prefix(15).enumerated() { ifr[i] = c }
        var tv = timeval(tv_sec: Int(readTimeout), tv_usec: Int32((readTimeout - Double(Int(readTimeout))) * 1e6))
        let program = LoopbackFilter.program()
        var raw = [UInt8](); raw.reserveCapacity(program.count * 8)
        for ins in program {
            raw += [UInt8(ins.code & 0xff), UInt8(ins.code >> 8), ins.jt, ins.jf]
            raw += withUnsafeBytes(of: ins.k.littleEndian, Array.init)
        }
        let ok: Bool = raw.withUnsafeMutableBytes { insns in
            var prog = [UInt8](repeating: 0, count: 16)   // struct bpf_program { u_int bf_len; struct bpf_insn *bf_insns; }
            prog.withUnsafeMutableBytes {
                $0.storeBytes(of: UInt32(program.count), toByteOffset: 0, as: UInt32.self)
                $0.storeBytes(of: insns.baseAddress, toByteOffset: 8, as: UnsafeMutableRawPointer?.self)
            }
            return ioctl(f, LoopbackCapture.iow(102, 4, read: true), &blen) == 0          // BIOCSBLEN
                && ifr.withUnsafeMutableBytes { ioctl(f, LoopbackCapture.iow(108, 32), $0.baseAddress!) } == 0   // BIOCSETIF
                && ioctl(f, LoopbackCapture.iow(112, 4), &one) == 0                       // BIOCIMMEDIATE
                && ioctl(f, LoopbackCapture.iow(119, 4), &one) == 0                       // BIOCSSEESENT
                && ioctl(f, LoopbackCapture.iow(109, MemoryLayout<timeval>.size), &tv) == 0   // BIOCSRTIMEOUT
                && prog.withUnsafeMutableBytes { ioctl(f, LoopbackCapture.iow(103, 16), $0.baseAddress!) } == 0  // BIOCSETF
        }
        guard ok else { close(f); return nil }
        fd = f
        buffer = [UInt8](repeating: 0, count: Int(blen))
    }

    deinit { close(fd) }

    /// Blocks until packets arrive (or the read timeout passes) and returns the captured frames.
    public func read() -> [[UInt8]] {
        let n = buffer.withUnsafeMutableBytes { Darwin.read(fd, $0.baseAddress, $0.count) }
        guard n > 0 else { return [] }
        return Self.frames(in: buffer, count: n)
    }

    /// Splits a BPF read buffer: `struct bpf_hdr { timeval32 bh_tstamp; u_int32 bh_caplen, bh_datalen; u_short bh_hdrlen; }`
    /// before every frame, each record padded to 4 bytes.
    public static func frames(in b: [UInt8], count: Int) -> [[UInt8]] {
        var out: [[UInt8]] = [], at = 0
        func u32(_ o: Int) -> Int { Int(b[o]) | Int(b[o + 1]) << 8 | Int(b[o + 2]) << 16 | Int(b[o + 3]) << 24 }
        while at + 18 <= count {
            let caplen = u32(at + 8), hdrlen = Int(b[at + 16]) | Int(b[at + 17]) << 8
            guard hdrlen >= 18, at + hdrlen + caplen <= count else { break }
            out.append(Array(b[(at + hdrlen)..<(at + hdrlen + caplen)]))
            at += (hdrlen + caplen + 3) & ~3
        }
        return out
    }
}
