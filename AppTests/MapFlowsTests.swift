import XCTest
import MapKit
import RatMonitor
@testable import Rat

/// The map's moving pulses: which way a line carries traffic, when pulses run (never while nobody can see them or
/// nothing moves), the layers that draw them, and the map redrawing only when what it draws changes.
@MainActor
final class MapFlowsTests: XCTestCase {
    func testDirectionFromRates() {
        XCTAssertEqual(FlowDirection(rateIn: 0, rateOut: 0), .idle)
        XCTAssertEqual(FlowDirection(rateIn: 300, rateOut: 200), .idle, "keep-alives")
        XCTAssertEqual(FlowDirection(rateIn: 200_000, rateOut: 3_000), .down, "a download's ACKs go up")
        XCTAssertEqual(FlowDirection(rateIn: 2_000, rateOut: 300_000), .up)
        XCTAssertEqual(FlowDirection(rateIn: 40_000, rateOut: 35_000), .both, "a call or a WebSocket")
        XCTAssertEqual(FlowDirection(rateIn: 0, rateOut: 600), .up)
    }

    func testPulsesRunOnlyWhenSeenAndMoving() {
        XCTAssertTrue(MapFlows.animates(visible: true, reduceMotion: false, flows: [.idle, .down]))
        XCTAssertFalse(MapFlows.animates(visible: false, reduceMotion: false, flows: [.down]), "covered, minimized or hidden")
        XCTAssertFalse(MapFlows.animates(visible: true, reduceMotion: true, flows: [.down]), "Reduce Motion")
        XCTAssertFalse(MapFlows.animates(visible: true, reduceMotion: false, flows: [.idle, .idle]), "an idle map draws no frames")
        XCTAssertEqual(MapFlows.summary(flows: [.down, .both, .idle], animating: true), "2 moving")
        XCTAssertEqual(MapFlows.summary(flows: [.down], animating: false), "paused")
        XCTAssertEqual(MapFlows.summary(flows: [.idle], animating: false), "idle")
    }

    func testRunsAndPhases() {
        XCTAssertTrue(MapFlows.runs(flow: .idle, fast: true).isEmpty)
        XCTAssertEqual(MapFlows.runs(flow: .up, fast: false).map(\.reverse), [false], "out from this Mac")
        XCTAssertEqual(MapFlows.runs(flow: .down, fast: false).map(\.reverse), [true], "in from the server")
        XCTAssertEqual(MapFlows.runs(flow: .both, fast: false).map(\.sent), [true, false])
        XCTAssertEqual(MapFlows.runs(flow: .both, fast: false).map(\.offset), [0, 0.5], "half a line apart")
        XCTAssertEqual(MapFlows.runs(flow: .down, fast: true).count, 2, "a fast line carries two pulses")
        XCTAssertEqual(MapFlows.phase(time: 0), 0)
        XCTAssertEqual(MapFlows.phase(time: MapFlows.travelTime / 2), 0.5, accuracy: 1e-9)
        XCTAssertEqual(MapFlows.phase(time: MapFlows.travelTime * 3.25), 0.25, accuracy: 1e-9)
        XCTAssertEqual(MapFlows.phase(time: 0, offset: -0.25), 0.75, accuracy: 1e-9)
        XCTAssertEqual(MapFlows.framesPerSecond, 30, "the frame budget")
    }

    private func point(_ city: String, _ lat: Double, _ lon: Double) -> GeoPoint {
        GeoPoint(coordinate: .init(latitude: lat, longitude: lon), city: city, country: "X")
    }

    /// A line's traffic is the sum of the connections it stands for; both hops of a proxied one carry it.
    func testALinesTrafficIsItsConnectionsSum() {
        let paris = point("Paris", 48.86, 2.35), stockholm = point("Stockholm", 59.33, 18.07), madrid = point("Madrid", 40.42, -3.7)
        var app = AppEntry(identity: AppIdentity(id: "/Applications/A.app", name: "A", bundlePath: "/Applications/A.app", isSystem: false))
        app.remotes = [
            RemoteHost(address: "203.0.113.1", host: "a", port: 443, proto: "TCP", geo: paris, rateIn: 30_000, rateOut: 1_000),
            RemoteHost(address: "203.0.113.2", host: "b", port: 443, proto: "TCP", geo: paris, rateIn: 0, rateOut: 25_000),
            RemoteHost(address: "198.51.100.30", host: "c", port: 443, proto: "TCP", geo: madrid,
                       via: ProxyHop(kind: "SOCKS5", process: "ssh", listener: "127.0.0.1:1080", server: "192.0.2.10", serverGeo: stockholm), rateIn: 90_000),
        ]
        let g = MapPane.graph(apps: [app], selection: nil, filter: MonitorFilter(), me: point("Berlin", 52.5, 13.4))
        let arcs = Dictionary(uniqueKeysWithValues: g.arcs.map { ($0.id, $0) })
        XCTAssertEqual(arcs["me>Paris|X"]?.rateIn, 30_000)
        XCTAssertEqual(arcs["me>Paris|X"]?.flow, .both)
        XCTAssertEqual(arcs["me>Stockholm|X"]?.flow, .down, "the hop to the proxy server")
        XCTAssertEqual(arcs["Stockholm|X>Madrid|X"]?.flow, .down, "and on to the destination")
    }

    func testTheMapRedrawsOnlyWhenWhatItDrawsChanges() {
        let paris = point("Paris", 48.86, 2.35), rome = point("Rome", 41.9, 12.5)
        let fit = MapPane.region(fitting: [paris.coordinate, rome.coordinate])
        func layer(_ nodes: [GeoPoint], rate: Double = 0, fit f: MKCoordinateRegion? = nil) -> MapLayer {
            MapLayer(nodes: nodes.map { MapPane.Node(id: $0.city, point: $0, highlighted: false, proxy: false) },
                     arcs: nodes.map { MapPane.Arc(id: "me>\($0.city)", coords: [], highlighted: false, proxied: false, rateIn: rate) },
                     me: nil, fit: f ?? fit, camera: MapCameraTicks())
        }
        XCTAssertEqual(layer([paris, rome]), layer([paris, rome], rate: 500_000), "traffic numbers alone do not redraw the map")
        XCTAssertNotEqual(layer([paris, rome]), layer([paris]))
        XCTAssertNotEqual(layer([paris, rome]), layer([paris, rome], fit: MapPane.region(fitting: [paris.coordinate])), "the camera follows a new region")
        XCTAssertTrue(MapLayer.sameRegion(fit, MapPane.region(fitting: [rome.coordinate, paris.coordinate])), "the same pins in another order are the same view")
    }

    func testPulseLayersComeAndGoWithTheirLines() {
        let host = PulseHost(frame: CGRect(x: 0, y: 0, width: 400, height: 300))
        let line = [CGPoint(x: 10, y: 10), CGPoint(x: 200, y: 120), CGPoint(x: 380, y: 280)]
        host.show([.init(id: "a", points: line, flow: .down, fast: false), .init(id: "b", points: line, flow: .both, fast: true)])
        XCTAssertEqual(host.pulseCount, 4 + 16, "a head and three trail dots per pulse: 1 pulse, then 4")
        let first = host.layer?.sublayers?.first
        XCTAssertNotNil(first?.animation(forKey: "flow"))
        XCTAssertEqual((first?.animation(forKey: "flow") as? CAKeyframeAnimation)?.duration, MapFlows.travelTime)
        XCTAssertEqual((first?.animation(forKey: "flow") as? CAKeyframeAnimation)?.preferredFrameRateRange.maximum, 30)
        host.show([.init(id: "a", points: line, flow: .down, fast: false), .init(id: "b", points: line, flow: .both, fast: true)])
        XCTAssertTrue(host.layer?.sublayers?.first === first, "an unchanged line keeps its layers (no restart)")
        host.show([.init(id: "a", points: line.map { CGPoint(x: $0.x + 5, y: $0.y) }, flow: .down, fast: false)])
        XCTAssertEqual(host.pulseCount, 4, "a moved camera rebuilds the line; a gone line goes")
        host.show([])
        XCTAssertEqual(host.pulseCount, 0, "paused: no layers, no frames")
        XCTAssertTrue(host.layer?.sublayers?.isEmpty ?? true)
    }

    /// Each row's rate is how much its counters grew since the last pass; a closed socket is not negative traffic.
    func testRowRatesComeFromTheirCountersGrowth() async throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("rat-flows-\(UUID())")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        addTeardownBlock { try? FileManager.default.removeItem(at: dir) }
        let l = Ledger(directory: dir, helperInstalled: false, names: HostNames(resolve: { _ in nil }))
        let path = "/Applications/A.app/Contents/MacOS/A"
        let conns = [ObservedConnection(pid: 5, processPath: path, proto: .tcp, remoteAddress: "203.0.113.1", remotePort: 443, localPort: 50000, tcpState: "ESTABLISHED"),
                     ObservedConnection(pid: 5, processPath: path, proto: .tcp, remoteAddress: "203.0.113.1", remotePort: 443, localPort: 50001, tcpState: "ESTABLISHED")]
        func flow(_ port: Int, _ i: UInt64, _ o: UInt64) -> FlowCounter { FlowCounter(pid: 5, proto: .tcp, localPort: port, remoteAddress: "203.0.113.1", remotePort: 443, bytesIn: i, bytesOut: o) }
        // The passes' own times: a slow machine (CI) between two passes does not change the rate.
        let t0 = Date()
        await l.ingest(conns, [], flows: [flow(50000, 100_000, 1_000), flow(50001, 0, 0)], now: t0)
        XCTAssertEqual(l.apps.first?.remotes.first?.rateIn, 0, "no earlier pass to compare with")
        await l.ingest(conns, [], flows: [flow(50000, 400_000, 2_000), flow(50001, 0, 0)], now: t0 + 1.5)
        let r = try XCTUnwrap(l.apps.first?.remotes.first)
        XCTAssertEqual(r.rateIn, 300_000 / 1.5, accuracy: 1, "300 KB in a 1.5 s pass")
        XCTAssertEqual(r.rateOut, 1_000 / 1.5, accuracy: 1)
        XCTAssertEqual(FlowDirection(rateIn: r.rateIn, rateOut: r.rateOut), .down)
        await l.ingest(Array(conns.suffix(1)), [], flows: [flow(50001, 0, 0)], now: t0 + 3)
        XCTAssertEqual(l.apps.first?.remotes.first?.rateIn, 0, "the busy socket closed: the sum dropped, nothing moves")
    }

    func testCachesStayBounded() {
        let names = HostNames(resolve: { _ in nil })
        func address(_ i: Int) -> String { "100.\(64 + i / 65_536).\(i / 256 % 256).\(i % 256)" }
        for i in 0..<(GeoService.cacheLimit + 50) { _ = names.lookup(address(i)) }
        // The lookups answer in the background; wait for the last one.
        let deadline = Date().addingTimeInterval(30)
        while !names.lookup(address(GeoService.cacheLimit + 49)).settled && Date() < deadline { RunLoop.current.run(until: Date().addingTimeInterval(0.05)) }
        XCTAssertGreaterThan(names.cachedCount, 0)
        XCTAssertLessThanOrEqual(names.cachedCount, GeoService.cacheLimit)
        let geo = GeoService()
        for i in 0..<(GeoService.cacheLimit + 10) { _ = geo.lookup("10.\(i / 65_536).\(i / 256 % 256).\(i % 256)") }
        XCTAssertLessThanOrEqual(geo.cachedCount, GeoService.cacheLimit, "a Mac that stays up does not keep every address it saw")
    }
}
