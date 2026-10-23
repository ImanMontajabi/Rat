import SwiftUI
import MapKit

struct MapPane: View {
    @EnvironmentObject var ledger: Ledger
    let selection: String?
    @State private var position: MapCameraPosition = .region(MapPane.region(fitting: []))

    /// The visible region: every pin with some margin, never tighter than a regional view (15 degrees), so a lone
    /// "This Mac" pin does not zoom into streets or open water.
    static func region(fitting coords: [CLLocationCoordinate2D]) -> MKCoordinateRegion {
        guard let first = coords.first else {
            return MKCoordinateRegion(center: CLLocationCoordinate2D(latitude: 30, longitude: 10), span: MKCoordinateSpan(latitudeDelta: 100, longitudeDelta: 160))
        }
        var minLat = first.latitude, maxLat = first.latitude, minLon = first.longitude, maxLon = first.longitude
        for c in coords { minLat = min(minLat, c.latitude); maxLat = max(maxLat, c.latitude); minLon = min(minLon, c.longitude); maxLon = max(maxLon, c.longitude) }
        let lat = min(max((maxLat - minLat) * 1.5, 15), 150), lon = min(max((maxLon - minLon) * 1.5, 15), 340)
        return MKCoordinateRegion(center: CLLocationCoordinate2D(latitude: (minLat + maxLat) / 2, longitude: (minLon + maxLon) / 2),
                                  span: MKCoordinateSpan(latitudeDelta: lat, longitudeDelta: lon))
    }

    private var fitted: [CLLocationCoordinate2D] { graph.nodes.map(\.point.coordinate) + (ledger.myLocation.map { [$0.coordinate] } ?? []) }

    private struct Arc: Identifiable { let id: String; let coords: [CLLocationCoordinate2D]; let highlighted: Bool; let proxied: Bool }
    private struct Node: Identifiable { let id: String; let point: GeoPoint; let highlighted: Bool; var proxy: Bool }

    private var visibleApps: [AppEntry] { ledger.apps.filter { selection == nil || $0.id == selection } }

    private static func key(_ g: GeoPoint) -> String { "\(g.city)|\(g.country)" }

    /// Pins and lines. A connection through a local proxy is drawn in two hops, This Mac → proxy server → real
    /// destination (the second hop dashed); when the proxy's server is unknown, one dashed line to the destination.
    private var graph: (nodes: [Node], arcs: [Arc]) {
        var nodes: [String: Node] = [:], order: [String] = []
        var arcs: [String: Arc] = [:], arcOrder: [String] = []
        let highlighted = selection != nil
        func add(_ g: GeoPoint, proxy: Bool) {
            let k = Self.key(g)
            if nodes[k] == nil { nodes[k] = Node(id: k, point: g, highlighted: highlighted, proxy: proxy); order.append(k) }
            else if proxy { nodes[k]!.proxy = true }
        }
        func arc(from a: CLLocationCoordinate2D, _ aKey: String, to b: GeoPoint, proxied: Bool) {
            let id = "\(aKey)>\(Self.key(b))"
            guard aKey != Self.key(b), arcs[id] == nil else { return }
            arcs[id] = Arc(id: id, coords: Self.curve(from: a, to: b.coordinate), highlighted: highlighted, proxied: proxied)
            arcOrder.append(id)
        }
        let me = ledger.myLocation
        for a in visibleApps {
            for r in a.remotes {
                if let server = r.via?.serverGeo {
                    add(server, proxy: true)
                    if let me { arc(from: me.coordinate, "me", to: server, proxied: false) }
                    if let g = r.geo { add(g, proxy: false); arc(from: server.coordinate, Self.key(server), to: g, proxied: true) }
                } else if let g = r.geo {
                    add(g, proxy: false)
                    if let me { arc(from: me.coordinate, "me", to: g, proxied: r.via != nil) }
                }
            }
        }
        return (order.map { nodes[$0]! }, arcOrder.map { arcs[$0]! })
    }

    var body: some View {
        let g = graph
        ZStack {
            Map(position: $position) {
                ForEach(g.arcs) { a in
                    MapPolyline(coordinates: a.coords)
                        .stroke(a.highlighted ? (a.proxied ? Color.orange : Color.green) : Color(white: 0.75, opacity: 0.55),
                                style: StrokeStyle(lineWidth: a.highlighted ? 3 : 2, dash: a.proxied ? [7, 5] : []))
                }
                ForEach(g.nodes) { n in
                    Annotation(n.proxy ? "Proxy · \(n.point.city)" : n.point.city, coordinate: n.point.coordinate, anchor: .center) {
                        if n.proxy {
                            Image(systemName: "arrow.triangle.branch").font(.system(size: 9, weight: .bold)).foregroundStyle(.orange)
                                .frame(width: 18, height: 18)
                                .background(RoundedRectangle(cornerRadius: 5).fill(.white.opacity(0.9)))
                                .overlay(RoundedRectangle(cornerRadius: 5).stroke(n.highlighted ? Color.orange : .gray, lineWidth: 2))
                        } else {
                            Circle().fill(.white.opacity(0.85)).frame(width: 14, height: 14)
                                .overlay(Circle().stroke(n.highlighted ? Color.blue : .gray, lineWidth: 2))
                        }
                    }
                }
                if let me = ledger.myLocation {
                    Annotation("This Mac", coordinate: me.coordinate, anchor: .center) {
                        Image(systemName: "laptopcomputer").foregroundStyle(.white).padding(10)
                            .background(Circle().fill(.gray.opacity(0.7)))
                    }
                }
            }
            .onChange(of: fitted.map { "\($0.latitude),\($0.longitude)" }) { _, _ in
                withAnimation { position = .region(Self.region(fitting: fitted)) }
            }
            .onAppear { position = .region(Self.region(fitting: fitted)) }
            .mapStyle(.standard(elevation: .realistic, emphasis: .muted, pointsOfInterest: .excludingAll))
            .mapControls { MapZoomStepper() }

            if !ledger.geo.available {
                Text("Offline GeoIP database not found, so server locations are unavailable.")
                    .font(.callout).padding(14).background(.regularMaterial, in: RoundedRectangle(cornerRadius: 12))
            }
            Text("IP geolocation by DB-IP.com").font(.caption2).foregroundStyle(.secondary).padding(6)
                .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .bottomTrailing)
        }
    }

    /// Quadratic curve between two coordinates, bowed north so lines read as arcs.
    static func curve(from a: CLLocationCoordinate2D, to b: CLLocationCoordinate2D, steps: Int = 32) -> [CLLocationCoordinate2D] {
        let mid = CLLocationCoordinate2D(latitude: (a.latitude + b.latitude) / 2, longitude: (a.longitude + b.longitude) / 2)
        let dist = hypot(a.latitude - b.latitude, a.longitude - b.longitude)
        let ctrl = CLLocationCoordinate2D(latitude: min(mid.latitude + dist * 0.25, 85), longitude: mid.longitude)
        return (0...steps).map { i in
            let t = Double(i) / Double(steps), u = 1 - t
            return CLLocationCoordinate2D(latitude: u*u*a.latitude + 2*u*t*ctrl.latitude + t*t*b.latitude,
                                          longitude: u*u*a.longitude + 2*u*t*ctrl.longitude + t*t*b.longitude)
        }
    }
}
