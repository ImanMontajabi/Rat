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

/// Fully offline IP geolocation. Reads the DB-IP Lite city database bundled in Contents/Resources/Vendor;
/// no address ever leaves the machine.
final class GeoService: @unchecked Sendable {
    static let databaseName = "dbip-city-lite"
    private let db: GeoIP?
    private let lock = NSLock()
    private var cache: [String: GeoPoint?] = [:]

    var available: Bool { db != nil }

    init() {
        let env = ProcessInfo.processInfo.environment["RAT_GEOIP_DB"]
        let bundled = Bundle.main.url(forResource: Self.databaseName, withExtension: "mmdb", subdirectory: "Vendor")?.path
        let path = [env, bundled].compactMap { $0 }.first { FileManager.default.fileExists(atPath: $0) }
        db = path.flatMap { try? GeoIP(path: $0) }
        logger.notice("geoip database \(self.db == nil ? "missing" : "loaded", privacy: .public)")
    }

    func lookup(_ ip: String) -> GeoPoint? {
        if let hit = lock.withLock({ cache[ip] }) { return hit }
        let result = db?.locate(ip).map {
            GeoPoint(coordinate: .init(latitude: $0.latitude, longitude: $0.longitude), city: $0.city, country: $0.country)
        }
        lock.withLock { cache[ip] = .some(result) }
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

func registrableDomain(_ host: String) -> String {
    let parts = host.split(separator: ".")
    guard parts.count > 2, host.contains(where: { $0.isLetter }) else { return host }
    return parts.suffix(2).joined(separator: ".")
}

func isLocalAddress(_ a: String) -> Bool {
    a.hasPrefix("127.") || a.hasPrefix("10.") || a.hasPrefix("192.168.") || a.hasPrefix("169.254.") || a == "::1" ||
    a.hasPrefix("fe80:") || a.hasPrefix("fc") || a.hasPrefix("fd") || (a.hasPrefix("172.") && (Int(a.split(separator: ".")[1]) ?? 0).clamped(16...31))
}

private extension Int { func clamped(_ r: ClosedRange<Int>) -> Bool { r.contains(self) } }
