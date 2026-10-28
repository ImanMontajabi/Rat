import SwiftUI
import MapKit

struct MapPane: View {
    @EnvironmentObject var ledger: Ledger
    let selection: MonitorSelection?
    /// The list's search and filters: only the apps and connections they leave are drawn.
    var filter = MonitorFilter()

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

    private var visibleApps: [AppEntry] { filter.apps(ledger, settings: .shared).filter { selection == nil || $0.id == selection?.appID } }

    private static func key(_ g: GeoPoint) -> String { "\(g.city)|\(g.country)" }

    /// A line on the map, and the traffic of the connections it stands for on the last pass.
    struct Arc: Identifiable {
        let id: String
        let coords: [CLLocationCoordinate2D]
        let highlighted: Bool
        let proxied: Bool
        var rateIn = 0.0
        var rateOut = 0.0
        var flow: FlowDirection { FlowDirection(rateIn: rateIn, rateOut: rateOut) }
    }
    struct Node: Identifiable { let id: String; let point: GeoPoint; let highlighted: Bool; var proxy: Bool }

    /// Pins and lines. A connection through a local proxy is drawn in two hops, This Mac → proxy server → real
    /// destination (the second hop dashed); when the proxy's server is unknown, one dashed line to the destination.
    /// A line's traffic is the sum of its connections' (both hops of a proxied one carry it).
    static func graph(apps: [AppEntry], selection: MonitorSelection?, filter: MonitorFilter, me: GeoPoint?) -> (nodes: [Node], arcs: [Arc]) {
        var nodes: [String: Node] = [:], order: [String] = []
        var arcs: [String: Arc] = [:], arcOrder: [String] = []
        let highlighted = selection != nil
        func add(_ g: GeoPoint, proxy: Bool) {
            let k = key(g)
            if nodes[k] == nil { nodes[k] = Node(id: k, point: g, highlighted: highlighted, proxy: proxy); order.append(k) }
            else if proxy { nodes[k]!.proxy = true }
        }
        func arc(from a: CLLocationCoordinate2D, _ aKey: String, to b: GeoPoint, proxied: Bool, _ r: RemoteHost) {
            let id = "\(aKey)>\(key(b))"
            guard aKey != key(b) else { return }
            if arcs[id] == nil { arcs[id] = Arc(id: id, coords: curve(from: a, to: b.coordinate), highlighted: highlighted, proxied: proxied); arcOrder.append(id) }
            arcs[id]!.rateIn += r.rateIn; arcs[id]!.rateOut += r.rateOut
        }
        for a in apps {
            for r in a.remotes(for: selection) where filter.matches(r, of: a) {
                if let server = r.via?.serverGeo {
                    add(server, proxy: true)
                    if let me { arc(from: me.coordinate, "me", to: server, proxied: false, r) }
                    if let g = r.geo { add(g, proxy: false); arc(from: server.coordinate, key(server), to: g, proxied: true, r) }
                } else if let g = r.geo {
                    add(g, proxy: false)
                    if let me { arc(from: me.coordinate, "me", to: g, proxied: r.via != nil, r) }
                }
            }
        }
        return (order.map { nodes[$0]! }, arcOrder.map { arcs[$0]! })
    }

    @StateObject private var window = WindowVisibility()
    /// Not observed here: a pan moves the pulses, it does not rebuild the map.
    @State private var camera = MapCameraTicks()
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    var body: some View {
        let g = Self.graph(apps: visibleApps, selection: selection, filter: filter, me: ledger.myLocation)
        let fit = Self.region(fitting: g.nodes.map(\.point.coordinate) + (ledger.myLocation.map { [$0.coordinate] } ?? []))
        let flows = g.arcs.map(\.flow)
        let animating = MapFlows.animates(visible: window.visible, reduceMotion: reduceMotion, flows: flows)
        ZStack {
            MapReader { proxy in
                ZStack {
                    // Redrawn only when a pin or a line changes, not on every pass (MapKit draws on each update).
                    MapLayer(nodes: g.nodes, arcs: g.arcs, me: ledger.myLocation, fit: fit, camera: camera).equatable()
                    FlowOverlay(camera: camera,
                                lines: g.arcs.filter { $0.flow != .idle }.map { FlowOverlay.Line(id: $0.id, coords: $0.coords, flow: $0.flow, fast: max($0.rateIn, $0.rateOut) >= MapFlows.fastRate) },
                                proxy: proxy, paused: !animating)
                }
                .coordinateSpace(.named(FlowOverlay.space))
            }

            if !ledger.geo.available {
                Text("Offline GeoIP database not found, so server locations are unavailable.")
                    .font(.callout).padding(14).background(.regularMaterial, in: RoundedRectangle(cornerRadius: 12))
            }
            Text("IP geolocation by DB-IP.com").font(.caption2).foregroundStyle(.secondary).padding(6)
                .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .bottomTrailing)
            // The places on the map, for VoiceOver and the UI tests (map annotations are not reachable there).
            Text("Map").font(.system(size: 1)).foregroundStyle(.clear).allowsHitTesting(false)
                .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
                .accessibilityLabel("Map")
                .accessibilityValue(Self.summary(g.nodes.map { $0.proxy ? "Proxy · \($0.point.city)" : $0.point.city }))
                .accessibilityIdentifier("map-places")
            Text("Flows").font(.system(size: 1)).foregroundStyle(.clear).allowsHitTesting(false)
                .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topTrailing)
                .accessibilityLabel("Traffic on the map")
                .accessibilityValue(MapFlows.summary(flows: flows, animating: animating))
                .accessibilityIdentifier("map-flows")
        }
        .background(WindowVisibilityReader(visibility: window))
    }

    /// "Madrid, Proxy · Stockholm": the places drawn, sorted; "No servers" when the filter leaves none.
    static func summary(_ places: [String]) -> String { places.isEmpty ? "No servers" : places.sorted().joined(separator: ", ") }

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

/// The map with its pins and lines, apart from the moving pulses. It compares equal when nothing it draws changed,
/// so a pass that only changes traffic numbers does not make MapKit draw again, and the camera follows only when
/// the region that fits the pins changes (not when the same pins come in another order).
struct MapLayer: View, Equatable {
    let nodes: [MapPane.Node]
    let arcs: [MapPane.Arc]
    let me: GeoPoint?
    let fit: MKCoordinateRegion
    /// Told about every camera move (not compared).
    let camera: MapCameraTicks
    @State private var position: MapCameraPosition = .region(MapPane.region(fitting: []))

    static func == (a: MapLayer, b: MapLayer) -> Bool {
        a.me == b.me && sameRegion(a.fit, b.fit)
            && a.nodes.map { "\($0.id)|\($0.highlighted)|\($0.proxy)" } == b.nodes.map { "\($0.id)|\($0.highlighted)|\($0.proxy)" }
            && a.arcs.map { "\($0.id)|\($0.highlighted)|\($0.proxied)" } == b.arcs.map { "\($0.id)|\($0.highlighted)|\($0.proxied)" }
    }

    /// Regions within a hundredth of a degree are the same view.
    static func sameRegion(_ a: MKCoordinateRegion, _ b: MKCoordinateRegion) -> Bool {
        abs(a.center.latitude - b.center.latitude) < 0.01 && abs(a.center.longitude - b.center.longitude) < 0.01
            && abs(a.span.latitudeDelta - b.span.latitudeDelta) < 0.01 && abs(a.span.longitudeDelta - b.span.longitudeDelta) < 0.01
    }

    private var fitKey: String { String(format: "%.2f,%.2f,%.2f,%.2f", fit.center.latitude, fit.center.longitude, fit.span.latitudeDelta, fit.span.longitudeDelta) }

    var body: some View {
        Map(position: $position) {
            ForEach(arcs) { a in
                MapPolyline(coordinates: a.coords)
                    .stroke(a.highlighted ? (a.proxied ? Color.orange : Color.green) : Color(white: 0.75, opacity: 0.55),
                            style: StrokeStyle(lineWidth: a.highlighted ? 3 : 2, dash: a.proxied ? [7, 5] : []))
            }
            ForEach(nodes) { n in
                let city = [n.point.flag, n.point.city].filter { !$0.isEmpty }.joined(separator: " ")
                Annotation(n.proxy ? "Proxy · \(city)" : city, coordinate: n.point.coordinate, anchor: .center) {
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
            if let me {
                Annotation("This Mac", coordinate: me.coordinate, anchor: .center) {
                    Image(systemName: "laptopcomputer").foregroundStyle(.white).padding(10)
                        .background(Circle().fill(.gray.opacity(0.7)))
                }
            }
        }
        .onMapCameraChange(frequency: .continuous) { camera.version &+= 1 }
        .onChange(of: fitKey) { _, _ in withAnimation { position = .region(fit) } }
        .onAppear { position = .region(fit) }
        .mapStyle(.standard(elevation: .realistic, emphasis: .muted, pointsOfInterest: .excludingAll))
        .mapControls { MapZoomStepper() }
    }
}
