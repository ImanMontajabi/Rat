import Foundation
import CoreLocation
import RatGeo
import os

private let logger = Logger(subsystem: "com.imanmontajabi.Rat", category: "geo")

struct GeoPoint: Hashable {
    var coordinate: CLLocationCoordinate2D
    var city: String
    var country: String
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

    init() {
        db = Self.bundledPath(Self.databaseName, env: "RAT_GEOIP_DB").flatMap { try? GeoIP(path: $0) }
        asn = Self.bundledPath(Self.asnDatabaseName, env: "RAT_GEOIP_ASN_DB").flatMap { try? ASNDatabase(path: $0) }
        logger.notice("geoip city \(self.db == nil ? "missing" : "loaded", privacy: .public), asn \(self.asn == nil ? "missing" : "loaded", privacy: .public)")
    }

    static func bundledPath(_ name: String, env: String) -> String? {
        let fromEnv = ProcessInfo.processInfo.environment[env]
        let bundled = Bundle.main.url(forResource: name, withExtension: "mmdb", subdirectory: "Vendor")?.path
        return [fromEnv, bundled].compactMap { $0 }.first { FileManager.default.fileExists(atPath: $0) }
    }

    func lookup(_ ip: String) -> GeoPoint? {
        if let hit = lock.withLock({ cache[ip] }) { return hit }
        let result = lock.withLock { db }?.locate(ip).map {
            GeoPoint(coordinate: .init(latitude: $0.latitude, longitude: $0.longitude), city: $0.city, country: $0.country)
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
        return GeoPoint(coordinate: .init(latitude: z.lat, longitude: z.lon), city: z.city, country: country)
    }
}

/// Reverse-DNS cache used to name remote hosts.
actor HostNames {
    private var cache: [String: String] = [:]

    func name(for ip: String) async -> String {
        if let c = cache[ip] { return c }
        let n: String = await Task.detached {
            var hints = addrinfo(); hints.ai_flags = AI_NUMERICHOST
            var res: UnsafeMutablePointer<addrinfo>?
            guard getaddrinfo(ip, nil, &hints, &res) == 0, let ai = res else { return ip }
            defer { freeaddrinfo(res) }
            var host = [CChar](repeating: 0, count: Int(NI_MAXHOST))
            return getnameinfo(ai.pointee.ai_addr, ai.pointee.ai_addrlen, &host, socklen_t(host.count), nil, 0, NI_NAMEREQD) == 0 ? String(cString: host) : ip
        }.value
        cache[ip] = n
        return n
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

func isLocalAddress(_ a: String) -> Bool {
    LocalRanges.shared.contains(a) || a.hasPrefix("127.") || a.hasPrefix("10.") || a.hasPrefix("192.168.") || a.hasPrefix("169.254.") || a == "::1" ||
    a.hasPrefix("fe80:") || a.hasPrefix("fc") || a.hasPrefix("fd") || (a.hasPrefix("172.") && (Int(a.split(separator: ".")[1]) ?? 0).clamped(16...31))
}

private extension Int { func clamped(_ r: ClosedRange<Int>) -> Bool { r.contains(self) } }
