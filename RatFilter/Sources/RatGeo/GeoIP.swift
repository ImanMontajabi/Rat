import Foundation

public struct GeoLocation: Equatable, Sendable {
    public var latitude: Double
    public var longitude: Double
    public var city: String
    public var country: String
    public var countryCode: String
}

/// Offline IP geolocation backed by a DB-IP Lite city database (CC BY 4.0, https://db-ip.com), or any file with
/// the GeoIP2 City layout (MaxMind GeoLite2-City / GeoIP2-City).
public final class GeoIP: @unchecked Sendable {
    public let db: MMDB

    public init(path: String) throws { db = try MMDB(path: path) }

    public func locate(_ address: String) -> GeoLocation? {
        guard let r = db.lookup(address), let lat = r["location"]?["latitude"]?.double, let lon = r["location"]?["longitude"]?.double else { return nil }
        return GeoLocation(latitude: lat, longitude: lon,
                           city: r["city"]?["names"]?["en"]?.string ?? "",
                           country: r["country"]?["names"]?["en"]?.string ?? "",
                           countryCode: r["country"]?["iso_code"]?.string ?? "")
    }
}

/// Who runs the network an address belongs to: `AS13335 Cloudflare, Inc.`. It is the network's owner (a cloud or
/// hosting provider for most services), not the vendor of the app or site.
public struct NetworkOwner: Equatable, Sendable {
    public var number: UInt32
    public var organization: String
    public init(number: UInt32, organization: String) { self.number = number; self.organization = organization }
    public var label: String { organization.isEmpty ? "AS\(number)" : "AS\(number) \(organization)" }
}

/// Offline ASN lookup backed by DB-IP "IP to ASN Lite" (CC BY 4.0) or MaxMind GeoLite2-ASN: both use the fields
/// `autonomous_system_number` and `autonomous_system_organization`.
public final class ASNDatabase: @unchecked Sendable {
    public let db: MMDB

    public init(path: String) throws { db = try MMDB(path: path) }

    public func owner(_ address: String) -> NetworkOwner? {
        guard let r = db.lookup(address), case .uint(let n)? = r["autonomous_system_number"], n > 0, n <= UInt64(UInt32.max) else { return nil }
        return NetworkOwner(number: UInt32(n), organization: r["autonomous_system_organization"]?.string ?? "")
    }
}

/// Approximate position of this Mac from its time zone, using the system's zone.tab. Works offline.
public enum TimeZoneLocator {
    public static func coordinates(forZone id: String = TimeZone.current.identifier, zoneTab: String? = nil) -> (lat: Double, lon: Double, city: String)? {
        let text = zoneTab ?? (try? String(contentsOfFile: "/usr/share/zoneinfo/zone.tab", encoding: .utf8)) ?? ""
        for line in text.split(separator: "\n") where !line.hasPrefix("#") {
            let f = line.split(separator: "\t")
            guard f.count >= 3, f[2] == id, let c = parseISO6709(String(f[1])) else { continue }
            return (c.lat, c.lon, id.split(separator: "/").last.map { $0.replacingOccurrences(of: "_", with: " ") } ?? id)
        }
        return nil
    }

    /// "+5230+01322" or "+403042-0740056" → degrees.
    static func parseISO6709(_ s: String) -> (lat: Double, lon: Double)? {
        guard let split = s.dropFirst().firstIndex(where: { $0 == "+" || $0 == "-" }) else { return nil }
        func deg(_ part: Substring, degDigits: Int) -> Double? {
            guard let sign = part.first, sign == "+" || sign == "-" else { return nil }
            let d = part.dropFirst()
            guard d.count >= degDigits + 2, let deg = Double(d.prefix(degDigits)), let min = Double(d.dropFirst(degDigits).prefix(2)) else { return nil }
            let sec = d.count >= degDigits + 4 ? (Double(d.dropFirst(degDigits + 2).prefix(2)) ?? 0) : 0
            return (sign == "-" ? -1 : 1) * (deg + min / 60 + sec / 3600)
        }
        guard let lat = deg(s[s.startIndex..<split], degDigits: 2), let lon = deg(s[split...], degDigits: 3) else { return nil }
        return (lat, lon)
    }
}
