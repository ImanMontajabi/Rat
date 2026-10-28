import Foundation
import CoreLocation
import RatGeo
import RatFilterCore
import os

private let logger = Logger(subsystem: "com.imanmontajabi.Rat", category: "geo")

struct GeoPoint: Hashable {
    var coordinate: CLLocationCoordinate2D
    var city: String
    var country: String
    /// ISO 3166-1 alpha-2 (`DE`), empty when the database has none.
    var countryCode: String = ""

    /// The country's flag (`🇩🇪`), or empty.
    var flag: String { Flag.emoji(countryCode) }
    /// "🇩🇪 Berlin, Germany"; the city is left out when the database has none.
    var place: String { [flag, [city, country].filter { !$0.isEmpty }.joined(separator: ", ")].filter { !$0.isEmpty }.joined(separator: " ") }
    static func == (a: GeoPoint, b: GeoPoint) -> Bool { a.city == b.city && a.country == b.country && a.coordinate.latitude == b.coordinate.latitude }
    func hash(into h: inout Hasher) { h.combine(city); h.combine(country); h.combine(coordinate.latitude) }
}

/// Fully offline IP geolocation and network owners. Reads the DB-IP Lite databases bundled in
/// Contents/Resources/Vendor (City for the map, ASN for "who runs this network"); no address ever leaves the machine.
final class GeoService: @unchecked Sendable {
    static let databaseName = "dbip-city-lite"
    static let asnDatabaseName = "dbip-asn-lite"
    private let lock = NSLock()
    private var db: GeoIP?
    private var asn: ASNDatabase?
    private var cache: [String: GeoPoint?] = [:]
    private var asnCache: [String: NetworkOwner?] = [:]

    var available: Bool { lock.withLock { db != nil } }
    var networksAvailable: Bool { lock.withLock { asn != nil } }

    enum Kind: String, CaseIterable, Identifiable, Sendable {
        case city, asn
        var id: String { rawValue }
        var bundledName: String { self == .city ? GeoService.databaseName : GeoService.asnDatabaseName }
    }

    /// The file each database was read from, with its metadata.
    struct Loaded: Equatable { var path: String; var type: String; var built: Date? }
    private var loaded: [Kind: Loaded] = [:]

    init() {
        for k in Kind.allCases {
            if let p = Self.bundledPath(k.bundledName, env: k == .city ? "RAT_GEOIP_DB" : "RAT_GEOIP_ASN_DB") { try? use(k, path: p) }
        }
        logger.notice("geoip city \(self.db == nil ? "missing" : "loaded", privacy: .public), asn \(self.asn == nil ? "missing" : "loaded", privacy: .public)")
    }

    func loadedFile(_ kind: Kind) -> Loaded? { lock.withLock { loaded[kind] } }

    /// Switches one database to another file, without a restart. A file that does not open, or does not answer
    /// like a database of that kind, throws and the current one stays in use.
    func use(_ kind: Kind, path: String) throws {
        let info = try Self.validate(kind, path: path)
        switch kind {
        case .city:
            let g = try GeoIP(path: path)
            lock.withLock { db = g; cache.removeAll(); loaded[.city] = info }
        case .asn:
            let a = try ASNDatabase(path: path)
            lock.withLock { asn = a; asnCache.removeAll(); loaded[.asn] = info }
        }
    }

    enum Invalid: LocalizedError {
        case notADatabase, wrongKind(String)
        var errorDescription: String? {
            switch self {
            case .notADatabase: return "This is not a MaxMind DB (.mmdb) file, or it is damaged."
            case .wrongKind(let k): return "This file does not hold \(k) data for well-known addresses."
            }
        }
    }

    /// Opens a file and checks that it answers like a City (coordinates) or ASN (network number) database.
    static func validate(_ kind: Kind, path: String) throws -> Loaded {
        let probes = ["8.8.8.8", "1.1.1.1", "2001:4860:4860::8888"]
        switch kind {
        case .city:
            guard let g = try? GeoIP(path: path) else { throw Invalid.notADatabase }
            guard probes.contains(where: { g.locate($0) != nil }) else { throw Invalid.wrongKind("city and location") }
            return Loaded(path: path, type: g.db.databaseType, built: g.db.buildDate)
        case .asn:
            guard let a = try? ASNDatabase(path: path) else { throw Invalid.notADatabase }
            guard probes.contains(where: { a.owner($0) != nil }) else { throw Invalid.wrongKind("network (ASN)") }
            return Loaded(path: path, type: a.db.databaseType, built: a.db.buildDate)
        }
    }

    static func bundledPath(_ name: String, env: String) -> String? {
        let fromEnv = ProcessInfo.processInfo.environment[env]
        let bundled = Bundle.main.url(forResource: name, withExtension: "mmdb", subdirectory: "Vendor")?.path
        return [fromEnv, bundled].compactMap { $0 }.first { FileManager.default.fileExists(atPath: $0) }
    }

    func lookup(_ ip: String) -> GeoPoint? {
        if let hit = lock.withLock({ cache[ip] }) { return hit }
        let result = lock.withLock { db }?.locate(ip).map {
            GeoPoint(coordinate: .init(latitude: $0.latitude, longitude: $0.longitude), city: $0.city, country: $0.country, countryCode: $0.countryCode)
        }
        lock.withLock { cache[ip] = .some(result) }
        return result
    }

    /// The network an address belongs to (`AS13335 Cloudflare, Inc.`): who runs the network, not the app's vendor.
    func network(_ ip: String) -> NetworkOwner? {
        if let hit = lock.withLock({ asnCache[ip] }) { return hit }
        let result = lock.withLock { asn }?.owner(ip)
        lock.withLock { asnCache[ip] = .some(result) }
        return result
    }

    /// Where this Mac probably is, from its time zone (offline).
    static func localPoint() -> GeoPoint? {
        guard let z = TimeZoneLocator.coordinates() else { return nil }
        let country = Locale.current.region.flatMap { Locale.current.localizedString(forRegionCode: $0.identifier) } ?? ""
        return GeoPoint(coordinate: .init(latitude: z.lat, longitude: z.lon), city: z.city, country: country, countryCode: Locale.current.region?.identifier ?? "")
    }
}

/// Reverse-DNS names for remote hosts. A pass never waits for DNS: `lookup` answers at once with the name if it is
/// known, or the address itself while a background lookup runs (at most four at a time, so a slow or dead DNS
/// server ties up four threads and nothing else). Addresses that have no name on the network (loopback,
/// unspecified, link-local) are never looked up.
final class HostNames: @unchecked Sendable {
    /// How long a connection may wait for its name before it is judged by address alone.
    static let grace: TimeInterval = 3

    private let lock = NSLock()
    private var cache: [String: String] = [:]
    private var pending: [String: Date] = [:]
    private let queue: OperationQueue = {
        let q = OperationQueue()
        q.name = "com.imanmontajabi.Rat.hostnames"
        q.maxConcurrentOperationCount = 4
        q.qualityOfService = .utility
        return q
    }()
    private let resolve: @Sendable (String) -> String?

    init(resolve: @escaping @Sendable (String) -> String? = HostNames.reverseLookup) { self.resolve = resolve }

    /// The name to show (the address until a name is known) and whether it is settled: known, never to be looked
    /// up, or waited for longer than `grace`.
    func lookup(_ ip: String, now: Date = Date()) -> (name: String, settled: Bool) {
        guard Self.hasNetworkName(ip) else { return (ip, true) }
        return lock.withLock {
            if let c = cache[ip] { return (c, true) }
            if let started = pending[ip] { return (ip, now.timeIntervalSince(started) >= Self.grace) }
            pending[ip] = now
            queue.addOperation { [resolve] in
                let name = resolve(ip) ?? ip
                self.lock.withLock { self.cache[ip] = name; self.pending[ip] = nil }
            }
            return (ip, false)
        }
    }

    func name(for ip: String) -> String { lookup(ip).name }

    /// Whether DNS can name the address: not loopback (127.0.0.0/8, ::1), unspecified (0.0.0.0, ::) or link-local
    /// (169.254.0.0/16, fe80::/10), nor anything that is not an address.
    static func hasNetworkName(_ ip: String) -> Bool {
        let literal = ip.split(separator: "%", maxSplits: 1).first.map(String.init) ?? ip   // fe80::1%en0
        var v4 = in_addr(), v6 = in6_addr()
        if inet_pton(AF_INET, literal, &v4) == 1 {
            let b = withUnsafeBytes(of: v4.s_addr) { Array($0) }
            return !(b[0] == 127 || b.allSatisfy { $0 == 0 } || (b[0] == 169 && b[1] == 254))
        }
        guard inet_pton(AF_INET6, literal, &v6) == 1 else { return false }
        let b = withUnsafeBytes(of: v6) { Array($0) }
        if b.allSatisfy({ $0 == 0 }) { return false }                                    // ::
        if b[..<15].allSatisfy({ $0 == 0 }) && b[15] == 1 { return false }               // ::1
        if b[0] == 0xfe && b[1] & 0xc0 == 0x80 { return false }                          // fe80::/10
        if b[..<10].allSatisfy({ $0 == 0 }) && b[10] == 0xff && b[11] == 0xff {          // ::ffff:a.b.c.d
            return hasNetworkName("\(b[12]).\(b[13]).\(b[14]).\(b[15])")
        }
        return true
    }

    static func reverseLookup(_ ip: String) -> String? {
        var hints = addrinfo(); hints.ai_flags = AI_NUMERICHOST
        var res: UnsafeMutablePointer<addrinfo>?
        guard getaddrinfo(ip, nil, &hints, &res) == 0, let ai = res else { return nil }
        defer { freeaddrinfo(res) }
        var host = [CChar](repeating: 0, count: Int(NI_MAXHOST))
        return getnameinfo(ai.pointee.ai_addr, ai.pointee.ai_addrlen, &host, socklen_t(host.count), nil, 0, NI_NAMEREQD) == 0 ? String(cString: host) : nil
    }
}

/// True for IPv4 and IPv6 literals (an IPv6 address contains letters, so "has letters" is not a hostname test).
func isIPLiteral(_ s: String) -> Bool {
    var v4 = in_addr(), v6 = in6_addr()
    return inet_pton(AF_INET, s, &v4) == 1 || inet_pton(AF_INET6, s, &v6) == 1
}

func registrableDomain(_ host: String) -> String {
    let parts = host.split(separator: ".")
    guard parts.count > 2, !isIPLiteral(host) else { return host }
    return parts.suffix(2).joined(separator: ".")
}

func isLocalAddress(_ a: String) -> Bool { LocalNetwork.contains(a) }

/// A country's flag from its ISO 3166-1 alpha-2 code: each letter becomes its regional indicator symbol (`DE` →
/// 🇩🇪). Empty for anything that is not a region code (the databases use `ZZ` for unknown); `EU` is a flag too.
enum Flag {
    private static let regions = Set(Locale.Region.isoRegions.map(\.identifier).filter { $0.count == 2 }).subtracting(["ZZ"]).union(["EU"])

    static func emoji(_ code: String) -> String {
        let c = code.uppercased()
        guard regions.contains(c) else { return "" }
        return String(String.UnicodeScalarView(c.unicodeScalars.compactMap { UnicodeScalar(0x1F1E6 + $0.value - 65) }))
    }
}

/// Traffic that stays near this Mac, which Hide Local leaves out: loopback, link-local, private (LAN) and the
/// user's own ranges (`LocalNetwork`), multicast and broadcast (Bonjour's 224.0.0.251 and ff02::fb, SSDP), and mDNS
/// (UDP 5353) whatever its address.
func isLocalTraffic(address: String, proto: String, port: Int) -> Bool {
    if proto.uppercased() == "UDP" && port == 5353 { return true }
    if address == "255.255.255.255" || address.lowercased().hasPrefix("ff") { return true }
    if let first = address.split(separator: ".").first.flatMap({ Int($0) }), address.contains("."), !address.contains(":"), (224...239).contains(first) { return true }
    return LocalNetwork.contains(address)
}
