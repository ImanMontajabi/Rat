import CoreGraphics
import Foundation

/// A place on the map (a city), chosen by clicking its pin or a line to it. The inspector then shows the apps and
/// connections that go there.
struct MapPlace: Hashable {
    /// The map's key for the place (`MapDestinations.key`): the pin and every line that ends there share it.
    let key: String
    let point: GeoPoint
    init(_ point: GeoPoint) { self.key = MapDestinations.key(point); self.point = point }
    static func == (a: MapPlace, b: MapPlace) -> Bool { a.key == b.key }
    func hash(into h: inout Hasher) { h.combine(key) }
}

/// One connection that goes to a place, with the app that holds it.
struct DestinationConnection: Identifiable {
    let app: AppEntry
    let remote: RemoteHost
    var id: String { app.id + "|" + remote.id }
    /// Reaches the place through a local proxy whose server is there (the place is the proxy's, not the destination's).
    var throughProxyServer: Bool
}

/// An app with connections to a place, and what they moved.
struct DestinationApp: Identifiable {
    let app: AppEntry
    var connections = 0
    var bytesIn: UInt64 = 0
    var bytesOut: UInt64 = 0
    var rateIn = 0.0
    var rateOut = 0.0
    var id: String { app.id }
}

/// Everything the map shows going to one place.
struct DestinationSummary {
    let place: MapPlace
    var connections: [DestinationConnection] = []
    var apps: [DestinationApp] = []
    var bytesIn: UInt64 { apps.reduce(0) { $0 + $1.bytesIn } }
    var bytesOut: UInt64 { apps.reduce(0) { $0 + $1.bytesOut } }
    var rateIn: Double { apps.reduce(0) { $0 + $1.rateIn } }
    var rateOut: Double { apps.reduce(0) { $0 + $1.rateOut } }
}

enum MapDestinations {
    /// The key of a place on the map: the city and its country (two cities may share a name).
    static func key(_ g: GeoPoint) -> String { "\(g.city)|\(g.country)" }

    /// The connections the map draws to `place`, with the same scope as the map: the listed apps (`apps`, already
    /// filtered by the list), the row selected in the list, and the filter. A connection through a local proxy goes
    /// to its destination and to the proxy's server, as its two lines do.
    @MainActor static func summary(_ place: MapPlace, apps: [AppEntry], selection: MonitorSelection?, filter: MonitorFilter) -> DestinationSummary {
        var s = DestinationSummary(place: place)
        var byApp: [String: Int] = [:]
        for a in apps where selection == nil || selection?.appID == a.id {
            for r in a.remotes(for: selection) where filter.matches(r, of: a) {
                let toDestination = r.geo.map(key) == place.key
                let toProxyServer = r.via?.serverGeo.map(key) == place.key
                guard toDestination || toProxyServer else { continue }
                s.connections.append(DestinationConnection(app: a, remote: r, throughProxyServer: !toDestination))
                let i: Int
                if let k = byApp[a.id] { i = k } else { i = s.apps.count; byApp[a.id] = i; s.apps.append(DestinationApp(app: a)) }
                s.apps[i].connections += 1
                s.apps[i].bytesIn += r.bytesIn; s.apps[i].bytesOut += r.bytesOut
                s.apps[i].rateIn += r.rateIn; s.apps[i].rateOut += r.rateOut
            }
        }
        // The busiest first, then by name, so the list does not jump while nothing moves.
        s.apps.sort { a, b in
            let ra: Double = a.rateIn + a.rateOut, rb: Double = b.rateIn + b.rateOut
            if ra != rb { return ra > rb }
            let ba: UInt64 = a.bytesIn + a.bytesOut, bb: UInt64 = b.bytesIn + b.bytesOut
            if ba != bb { return ba > bb }
            return a.app.identity.name < b.app.identity.name
        }
        s.connections.sort { a, b in
            let ra: Double = a.remote.rateIn + a.remote.rateOut, rb: Double = b.remote.rateIn + b.remote.rateOut
            if ra != rb { return ra > rb }
            if a.app.identity.name != b.app.identity.name { return a.app.identity.name < b.app.identity.name }
            return a.remote.host < b.remote.host
        }
        return s
    }

    /// What a click on the map at `point` chose: the nearest pin within `pinRadius`, else the nearest line within
    /// `lineDistance` (a line selects the place it ends at), else nothing. Points are in one coordinate space.
    static func hit(_ point: CGPoint, pins: [(key: String, at: CGPoint)], lines: [(key: String, points: [CGPoint])],
                    pinRadius: CGFloat = 12, lineDistance: CGFloat = 6) -> String? {
        func distance(_ a: CGPoint, _ b: CGPoint) -> CGFloat { hypot(a.x - b.x, a.y - b.y) }
        if let pin = pins.map({ ($0.key, distance(point, $0.at)) }).filter({ $0.1 <= pinRadius }).min(by: { $0.1 < $1.1 }) { return pin.0 }
        var best: (String, CGFloat)?
        for l in lines {
            for (a, b) in zip(l.points, l.points.dropFirst()) {
                let d = segmentDistance(point, a, b)
                if d <= lineDistance, best == nil || d < best!.1 { best = (l.key, d) }
            }
        }
        return best?.0
    }

    /// The distance from `p` to the segment `a`–`b`.
    static func segmentDistance(_ p: CGPoint, _ a: CGPoint, _ b: CGPoint) -> CGFloat {
        let dx = b.x - a.x, dy = b.y - a.y
        let length2 = dx * dx + dy * dy
        let t = length2 == 0 ? 0 : max(0, min(1, ((p.x - a.x) * dx + (p.y - a.y) * dy) / length2))
        return hypot(p.x - (a.x + t * dx), p.y - (a.y + t * dy))
    }
}
