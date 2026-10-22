import Foundation
import CoreLocation
import os

private let logger = Logger(subsystem: "com.imanmontajabi.Rat", category: "geo")

struct GeoPoint: Hashable {
    var coordinate: CLLocationCoordinate2D
    var city: String
    var country: String
    static func == (a: GeoPoint, b: GeoPoint) -> Bool { a.city == b.city && a.country == b.country && a.coordinate.latitude == b.coordinate.latitude }
    func hash(into h: inout Hasher) { h.combine(city); h.combine(country); h.combine(coordinate.latitude) }
}

/// Opt-in IP geolocation. Looking an address up sends it to ipwho.is, so the UI keeps this off until the user enables it.
actor GeoService {
    private var cache: [String: GeoPoint?] = [:]
    private var inFlight = Set<String>()

    func cached(_ ip: String) -> GeoPoint?? { cache[ip] }

    /// `ip` empty means "this machine's public address".
    func lookup(_ ip: String) async -> GeoPoint? {
        if let hit = cache[ip] { return hit }
        guard !inFlight.contains(ip) else { return nil }
        inFlight.insert(ip); defer { inFlight.remove(ip) }
        guard let url = URL(string: "https://ipwho.is/\(ip)?fields=success,latitude,longitude,city,country") else { return nil }
        do {
            let (data, _) = try await URLSession.shared.data(from: url)
            guard let j = try JSONSerialization.jsonObject(with: data) as? [String: Any], j["success"] as? Bool == true,
                  let lat = j["latitude"] as? Double, let lon = j["longitude"] as? Double else { cache[ip] = .some(nil); return nil }
            let p = GeoPoint(coordinate: .init(latitude: lat, longitude: lon), city: j["city"] as? String ?? "", country: j["country"] as? String ?? "")
            cache[ip] = p
            logger.notice("geolocated one address")
            return p
        } catch {
            logger.error("geo lookup failed: \(error.localizedDescription, privacy: .public)")
            return nil
        }
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
