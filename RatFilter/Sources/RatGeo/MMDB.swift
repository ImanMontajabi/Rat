import Foundation

/// Minimal MaxMind DB (.mmdb) reader: enough to look up an IP and decode the record.
/// Spec: https://maxmind.github.io/MaxMind-DB/
public final class MMDB: @unchecked Sendable {
    public enum Value: Equatable {
        case string(String), double(Double), uint(UInt64), int(Int64), bool(Bool)
        case map([String: Value]), array([Value]), bytes(Data)

        public subscript(key: String) -> Value? { if case .map(let m) = self { return m[key] }; return nil }
        public var string: String? { if case .string(let s) = self { return s }; return nil }
        public var double: Double? { if case .double(let d) = self { return d }; return nil }
    }

    public enum Failure: Error { case notMMDB, unsupported(String), corrupt }

    private let data: Data
    /// The file's metadata map (`database_type`, `build_epoch`, `description`, …).
    public let metadata: [String: Value]
    private let nodeCount: Int
    private let recordSize: Int
    private let ipVersion: Int
    private let treeSize: Int
    private let dataSectionStart: Int
    private var ipv4Start: Int?

    public convenience init(path: String) throws {
        try self.init(data: try Data(contentsOf: URL(fileURLWithPath: path), options: .alwaysMapped))
    }

    public init(data: Data) throws {
        self.data = data
        let marker = Data([0xAB, 0xCD, 0xEF] + Array("MaxMind.com".utf8))
        guard let r = data.range(of: marker, options: .backwards) else { throw Failure.notMMDB }
        var reader = Decoder(data: data, base: r.upperBound, pointerBase: r.upperBound)
        guard case .map(let meta) = try reader.decode(at: r.upperBound).value,
              case .uint(let nc)? = meta["node_count"], case .uint(let rs)? = meta["record_size"],
              case .uint(let ipv)? = meta["ip_version"] else { throw Failure.corrupt }
        metadata = meta
        nodeCount = Int(nc); recordSize = Int(rs); ipVersion = Int(ipv)
        guard [24, 28, 32].contains(recordSize) else { throw Failure.unsupported("record size \(recordSize)") }
        guard [4, 6].contains(ipVersion), nodeCount > 0, nodeCount < Int(Int32.max) else { throw Failure.corrupt }
        treeSize = recordSize * 2 / 8 * nodeCount
        dataSectionStart = treeSize + 16
        // A file whose search tree does not fit before the metadata is truncated or not what it claims.
        guard dataSectionStart <= r.lowerBound else { throw Failure.corrupt }
        _ = reader
        // IPv4 addresses live under ::/96 in an IPv6 tree; found once here so lookups only read.
        if ipVersion == 6 {
            var node = 0
            for _ in 0..<96 where node < nodeCount { node = readNode(node, bit: 0) }
            ipv4Start = node
        }
    }

    /// `database_type`, e.g. "DBIP-City-Lite" or "GeoLite2-ASN".
    public var databaseType: String { metadata["database_type"]?.string ?? "" }

    /// When the file was built (`build_epoch`).
    public var buildDate: Date? {
        guard case .uint(let e)? = metadata["build_epoch"] else { return nil }
        return Date(timeIntervalSince1970: TimeInterval(e))
    }

    /// Decoded record for an IPv4/IPv6 address string, or nil if not in the database.
    public func lookup(_ address: String) -> Value? {
        guard let bits = Self.bits(address) else { return nil }
        var node = 0
        var path = bits
        if ipVersion == 6, bits.count == 32 {
            node = ipv4Start ?? nodeCount
        } else if ipVersion == 4, bits.count == 128 { return nil }
        for bit in path where node < nodeCount { node = readNode(node, bit: bit) }
        path.removeAll()
        guard node > nodeCount else { return nil }
        let offset = treeSize + (node - nodeCount)
        guard offset >= dataSectionStart, offset < data.count else { return nil }
        var d = Decoder(data: data, base: dataSectionStart, pointerBase: dataSectionStart)
        return (try? d.decode(at: offset))?.value
    }

    private func readNode(_ n: Int, bit: Int) -> Int {
        let o = n * recordSize / 4
        // Every read stays inside the file; a bad tree ends the search (as "not found").
        guard o >= 0, o + recordSize / 4 <= data.count else { return nodeCount }
        let b = { (i: Int) -> Int in Int(self.data[self.data.startIndex + o + i]) }
        switch recordSize {
        case 24: return bit == 0 ? (b(0) << 16 | b(1) << 8 | b(2)) : (b(3) << 16 | b(4) << 8 | b(5))
        case 28:
            return bit == 0 ? (((b(3) & 0xF0) << 20) | b(0) << 16 | b(1) << 8 | b(2))
                            : (((b(3) & 0x0F) << 24) | b(4) << 16 | b(5) << 8 | b(6))
        default: return bit == 0 ? (b(0) << 24 | b(1) << 16 | b(2) << 8 | b(3)) : (b(4) << 24 | b(5) << 16 | b(6) << 8 | b(7))
        }
    }

    static func bits(_ address: String) -> [Int]? {
        var v4 = in_addr(), v6 = in6_addr()
        if inet_pton(AF_INET, address, &v4) == 1 {
            return withUnsafeBytes(of: &v4) { Array($0) }.flatMap { byte in (0..<8).map { Int((byte >> (7 - $0)) & 1) } }
        }
        if inet_pton(AF_INET6, address, &v6) == 1 {
            return withUnsafeBytes(of: &v6) { Array($0) }.flatMap { byte in (0..<8).map { Int((byte >> (7 - $0)) & 1) } }
        }
        return nil
    }

    // MARK: data section decoder

    struct Decoder {
        let data: Data
        let base: Int
        let pointerBase: Int
        /// Values decoded so far. A record has a few dozen; a crafted file (pointer loops, maps of millions of
        /// entries) is cut off instead of keeping a lookup busy.
        var budget = 20_000

        func byte(_ i: Int) throws -> Int {
            guard i >= 0, data.startIndex + i < data.endIndex else { throw Failure.corrupt }
            return Int(data[data.startIndex + i])
        }

        func uint(_ at: Int, _ n: Int) throws -> UInt64 {
            var v: UInt64 = 0
            for i in 0..<n { v = v << 8 | UInt64(try byte(at + i)) }
            return v
        }

        mutating func decode(at start: Int, depth: Int = 0) throws -> (value: Value, next: Int) {
            guard depth < 16, budget > 0 else { throw Failure.corrupt }
            budget -= 1
            var p = start
            let ctrl = try byte(p); p += 1
            var type = ctrl >> 5
            if type == 1 { // pointer
                let size = (ctrl >> 3) & 3
                let vvv = ctrl & 7
                var ptr: Int
                switch size {
                case 0: ptr = vvv << 8 | (try byte(p)); p += 1
                case 1: ptr = (vvv << 16 | Int(try uint(p, 2))) + 2048; p += 2
                case 2: ptr = (vvv << 24 | Int(try uint(p, 3))) + 526_336; p += 3
                default: ptr = Int(try uint(p, 4)); p += 4
                }
                ptr += pointerBase
                return (try decode(at: ptr, depth: depth + 1).value, p)
            }
            if type == 0 { type = 7 + (try byte(p)); p += 1 }
            var size = ctrl & 0x1F
            if size == 29 { size = 29 + (try byte(p)); p += 1 }
            else if size == 30 { size = 285 + Int(try uint(p, 2)); p += 2 }
            else if size == 31 { size = 65_821 + Int(try uint(p, 3)); p += 3 }
            switch type {
            case 2:
                guard p >= 0, data.startIndex + p + size <= data.endIndex else { throw Failure.corrupt }
                return (.string(String(decoding: data[(data.startIndex + p)..<(data.startIndex + p + size)], as: UTF8.self)), p + size)
            case 3:
                guard size == 8 else { throw Failure.corrupt }
                let bits = UInt64(try uint(p, 8)); return (.double(Double(bitPattern: bits)), p + 8)
            case 15:
                guard size == 4 else { throw Failure.corrupt }
                let bits = UInt32(try uint(p, 4)); return (.double(Double(Float(bitPattern: bits))), p + 4)
            case 4:
                guard p >= 0, data.startIndex + p + size <= data.endIndex else { throw Failure.corrupt }
                return (.bytes(data.subdata(in: (data.startIndex + p)..<(data.startIndex + p + size))), p + size)
            case 5, 6, 9, 10:
                guard size <= (type == 10 ? 16 : type == 9 ? 8 : type == 6 ? 4 : 2) else { throw Failure.corrupt }
                // uint128 keeps its low 64 bits.
                return (.uint(size == 0 ? 0 : try uint(p + max(size - 8, 0), min(size, 8))), p + size)
            case 8:
                guard size <= 4 else { throw Failure.corrupt }
                return (.int(Int64(Int32(truncatingIfNeeded: try uint(p, size)))), p + size)
            case 7:
                var m: [String: Value] = [:]
                for _ in 0..<size {
                    let k = try decode(at: p, depth: depth + 1); p = k.next
                    let v = try decode(at: p, depth: depth + 1); p = v.next
                    if let key = k.value.string { m[key] = v.value }
                }
                return (.map(m), p)
            case 11:
                var a: [Value] = []
                for _ in 0..<size { let v = try decode(at: p, depth: depth + 1); p = v.next; a.append(v.value) }
                return (.array(a), p)
            case 14: return (.bool(size != 0), p)
            default: throw Failure.unsupported("type \(type)")
            }
        }
    }
}
