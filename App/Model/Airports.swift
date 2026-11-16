import CoreLocation
import Foundation

/// Where an IATA airport code is, for a Cloudflare data centre (they are named after the nearest airport): a WARP
/// tunnel's exit, such as OpenWarp's `colo=DUS`, goes on the map at Düsseldorf. The table is
/// `Contents/Resources/airports.tsv`, built from OurAirports (public domain) by scripts/make-airports.py: one line
/// per code, `IATA \t latitude \t longitude \t country \t city`. Read once, on first use.
enum Airports {
    struct Place: Equatable {
        var latitude: Double
        var longitude: Double
        var countryCode: String
        var city: String
    }

    private static let table: [String: Place] = load(Bundle.main.url(forResource: "airports", withExtension: "tsv"))

    /// The airport for a three-letter code, or nil.
    static func place(_ code: String) -> Place? { table[code.uppercased()] }

    static func load(_ url: URL?) -> [String: Place] {
        guard let url, let text = try? String(contentsOf: url, encoding: .utf8) else { return [:] }
        return parse(text)
    }

    static func parse(_ text: String) -> [String: Place] {
        var out: [String: Place] = [:]
        out.reserveCapacity(6_000)
        for line in text.split(separator: "\n", omittingEmptySubsequences: true) {
            let f = line.split(separator: "\t", omittingEmptySubsequences: false)
            guard f.count == 5, f[0].count == 3, let lat = Double(f[1]), let lon = Double(f[2]), (-90...90).contains(lat), (-180...180).contains(lon),
                  f[3].count == 2 else { continue }
            out[String(f[0])] = Place(latitude: lat, longitude: lon, countryCode: String(f[3]), city: String(f[4]))
        }
        return out
    }

    /// A WARP tunnel's exit as a place on the map: the data centre's city, in the country Cloudflare reports for the
    /// exit (`loc`, which wins over the airport's own country when they differ). Nil for a code the table lacks.
    static func exit(colo: String, loc: String?) -> GeoPoint? {
        guard let p = place(colo) else { return nil }
        let cc = loc ?? p.countryCode
        return GeoPoint(coordinate: CLLocationCoordinate2D(latitude: p.latitude, longitude: p.longitude), city: p.city,
                        country: Countries.name(cc), countryCode: cc)
    }
}
