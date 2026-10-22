import SwiftUI
import MapKit

struct MapPane: View {
    @EnvironmentObject var ledger: Ledger
    let selection: String?
    @State private var position: MapCameraPosition = .automatic

    private struct Arc: Identifiable { let id: String; let coords: [CLLocationCoordinate2D]; let highlighted: Bool }
    private struct Node: Identifiable { let id: String; let point: GeoPoint; let highlighted: Bool }

    private var visibleApps: [AppEntry] { ledger.apps.filter { selection == nil || $0.id == selection } }

    private var nodes: [Node] {
        var seen = Set<String>(); var out: [Node] = []
        for a in visibleApps { for r in a.remotes { if let g = r.geo, seen.insert("\(g.city)|\(g.country)").inserted { out.append(Node(id: "\(g.city)|\(g.country)", point: g, highlighted: selection != nil)) } } }
        return out
    }

    private var arcs: [Arc] {
        guard let me = ledger.myLocation else { return [] }
        return nodes.map { Arc(id: $0.id, coords: Self.curve(from: me.coordinate, to: $0.point.coordinate), highlighted: $0.highlighted) }
    }

    var body: some View {
        ZStack {
            Map(position: $position) {
                ForEach(arcs) { a in
                    MapPolyline(coordinates: a.coords).stroke(a.highlighted ? Color.green : Color(white: 0.75, opacity: 0.55), lineWidth: a.highlighted ? 3 : 2)
                }
                ForEach(nodes) { n in
                    Annotation(n.point.city, coordinate: n.point.coordinate, anchor: .center) {
                        Circle().fill(.white.opacity(0.85)).frame(width: 14, height: 14)
                            .overlay(Circle().stroke(n.highlighted ? Color.blue : .gray, lineWidth: 2))
                    }
                }
                if let me = ledger.myLocation {
                    Annotation("This Mac", coordinate: me.coordinate, anchor: .center) {
                        Image(systemName: "laptopcomputer").foregroundStyle(.white).padding(10)
                            .background(Circle().fill(.gray.opacity(0.7)))
                    }
                }
            }
            .mapStyle(.standard(elevation: .realistic, emphasis: .muted, pointsOfInterest: .excludingAll))
            .mapControls { MapZoomStepper() }

            if !ledger.geoEnabled {
                VStack(spacing: 10) {
                    Image(systemName: "globe").font(.largeTitle)
                    Text("Show server locations").font(.headline)
                    Text("Looking up where servers are located sends their IP addresses to ipwho.is. Off by default.")
                        .font(.callout).multilineTextAlignment(.center).foregroundStyle(.secondary).frame(maxWidth: 300)
                    Button("Enable Lookups") { ledger.setGeoEnabled(true) }.buttonStyle(.borderedProminent)
                }
                .padding(24).background(.regularMaterial, in: RoundedRectangle(cornerRadius: 16))
            }
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
