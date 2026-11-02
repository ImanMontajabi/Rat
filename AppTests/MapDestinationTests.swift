import XCTest
import CoreGraphics
import MapKit
@testable import Rat

/// A place chosen on the map (its pin or a line to it): what goes there, what the map highlights, and which click
/// chooses what.
@MainActor
final class MapDestinationTests: XCTestCase {
    private func demo() throws -> Ledger {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("rat-place-\(UUID())")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        addTeardownBlock { try? FileManager.default.removeItem(at: dir) }
        let l = Ledger(directory: dir, helperInstalled: false, names: HostNames(resolve: { _ in nil }))
        l.installDemoData()
        return l
    }

    private func place(_ city: String, in l: Ledger) throws -> MapPlace {
        let g = try XCTUnwrap(l.apps.flatMap(\.remotes).compactMap { $0.geo ?? nil }.first { $0.city == city }
                              ?? l.apps.flatMap(\.remotes).compactMap { $0.via?.serverGeo }.first { $0.city == city }, city)
        return MapPlace(g)
    }

    /// Paris: Chrome's video helper and Telegram's call through the VPN, their bytes and their rates.
    func testAPlaceListsTheAppsAndConnectionsThatGoThere() throws {
        let l = try demo()
        let s = MapDestinations.summary(try place("Paris", in: l), apps: l.apps, selection: nil, filter: MonitorFilter())
        XCTAssertEqual(Set(s.apps.map(\.app.identity.name)), ["Google Chrome", "Telegram"])
        XCTAssertEqual(Set(s.connections.map(\.remote.host)), ["video.example.net", "demo3.example.com"])
        XCTAssertEqual(s.apps.map(\.connections), [1, 1])
        XCTAssertEqual(s.rateIn, 60_000, accuracy: 0.1); XCTAssertEqual(s.rateOut, 53_000, accuracy: 0.1)
        XCTAssertEqual(s.bytesIn, s.connections.reduce(0) { $0 + $1.remote.bytesIn })
        XCTAssertEqual(s.apps.first?.app.identity.name, "Google Chrome", "the busiest first (40 + 35 KB/s against 20 + 18)")
        XCTAssertTrue(s.connections.allSatisfy { !$0.throughProxyServer })
        XCTAssertEqual(DestinationInspector.counts(connections: s.connections.count, apps: s.apps.count), "2 connections from 2 apps")
    }

    /// Stockholm is also where Firefox's SOCKS proxy server is: its connection to Madrid passes there.
    func testAProxyServersPlaceListsTheConnectionsItCarries() throws {
        let l = try demo()
        let s = MapDestinations.summary(try place("Stockholm", in: l), apps: l.apps, selection: nil, filter: MonitorFilter())
        XCTAssertEqual(Set(s.apps.map(\.app.identity.name)), ["Steam", "macOS", "Firefox"])
        let firefox = try XCTUnwrap(s.connections.first { $0.app.identity.name == "Firefox" })
        XCTAssertTrue(firefox.throughProxyServer)
        XCTAssertEqual(firefox.remote.host, "news.example.org")
        XCTAssertTrue(DestinationInspector.detail(firefox).hasSuffix("via proxy to Madrid"), DestinationInspector.detail(firefox))
        // Madrid lists the same connection as going there.
        let madrid = MapDestinations.summary(try place("Madrid", in: l), apps: l.apps, selection: nil, filter: MonitorFilter())
        XCTAssertEqual(madrid.connections.first { $0.app.identity.name == "Firefox" }?.throughProxyServer, false)
    }

    /// The place follows the map's scope: the row selected in the list and the search.
    func testAPlaceFollowsTheSelectionAndTheFilter() throws {
        let l = try demo()
        let paris = try place("Paris", in: l)
        let chrome = try XCTUnwrap(l.apps.first { $0.identity.name == "Google Chrome" })
        let selected = MapDestinations.summary(paris, apps: l.apps, selection: MonitorSelection(appID: chrome.id), filter: MonitorFilter())
        XCTAssertEqual(selected.apps.map(\.app.identity.name), ["Google Chrome"])
        let searched = MapDestinations.summary(paris, apps: l.apps, selection: nil, filter: MonitorFilter(search: "vpn"))
        XCTAssertEqual(searched.connections.map(\.remote.host), ["demo3.example.com"], "only the connection through the VPN")
        let nowhere = MapDestinations.summary(MapPlace(GeoPoint(coordinate: .init(latitude: 43.65, longitude: -79.38), city: "Toronto", country: "Canada", countryCode: "CA")),
                                              apps: l.apps, selection: nil, filter: MonitorFilter())
        XCTAssertTrue(nowhere.apps.isEmpty); XCTAssertTrue(nowhere.connections.isEmpty)
    }

    /// With a place chosen, its pin is selected and only the lines of connections that go there are highlighted
    /// (both hops of one through a proxy).
    func testTheMapHighlightsTheChosenPlace() throws {
        let l = try demo()
        let madrid = try place("Madrid", in: l)
        let g = MapPane.graph(apps: l.apps, selection: nil, filter: MonitorFilter(), me: l.myLocation, place: madrid.key)
        XCTAssertEqual(g.nodes.filter(\.selected).map(\.point.city), ["Madrid"])
        XCTAssertEqual(Set(g.arcs.filter(\.highlighted).map(\.id)), ["me>Madrid|Spain", "me>Stockholm|Sweden", "Stockholm|Sweden>Madrid|Spain"])
        XCTAssertFalse(g.arcs.first { $0.id == "me>Paris|France" }?.highlighted ?? true)
        XCTAssertEqual(g.arcs.first { $0.id == "Stockholm|Sweden>Madrid|Spain" }?.place, madrid.key, "a line chooses the place it ends at")
        // Without a place, the map highlights as before: everything while a row is selected, nothing otherwise.
        let plain = MapPane.graph(apps: l.apps, selection: nil, filter: MonitorFilter(), me: l.myLocation)
        XCTAssertTrue(plain.arcs.allSatisfy { !$0.highlighted }); XCTAssertTrue(plain.nodes.allSatisfy { !$0.selected })
        let steam = try XCTUnwrap(l.apps.first { $0.identity.name == "Steam" })
        let scoped = MapPane.graph(apps: [steam], selection: MonitorSelection(appID: steam.id), filter: MonitorFilter(), me: l.myLocation)
        XCTAssertTrue(scoped.arcs.allSatisfy(\.highlighted))
        XCTAssertEqual(MapPlacesOverlay.routeName(try XCTUnwrap(g.arcs.first { $0.id == "Stockholm|Sweden>Madrid|Spain" }), nodes: g.nodes, separator: "-"), "Stockholm-Madrid")
        XCTAssertEqual(MapPlacesOverlay.routeName(try XCTUnwrap(g.arcs.first { $0.id == "me>Paris|France" }), nodes: g.nodes, separator: "-"), "Paris")
    }

    /// The zoom buttons halve or double the span around the same center, between a street and the whole world; a
    /// click on MapKit's logo and Legal link is not a click on empty map.
    func testZoomScalesTheRegionAndTheAttributionCornerIsNotEmptyMap() {
        let r = MKCoordinateRegion(center: .init(latitude: 50, longitude: 10), span: .init(latitudeDelta: 40, longitudeDelta: 60))
        let closer = MapZoom.scaled(r, by: 0.5), farther = MapZoom.scaled(r, by: 2)
        XCTAssertEqual(closer.span.latitudeDelta, 20); XCTAssertEqual(closer.span.longitudeDelta, 30)
        XCTAssertEqual(closer.center.latitude, 50); XCTAssertEqual(farther.span.longitudeDelta, 120)
        XCTAssertEqual(MapZoom.scaled(MapZoom.scaled(r, by: 8), by: 8).span.latitudeDelta, 170, "never past the whole world")
        XCTAssertEqual(MapZoom.scaled(MKCoordinateRegion(center: r.center, span: .init(latitudeDelta: 0.015, longitudeDelta: 0.015)), by: 0.5).span.latitudeDelta, 0.01)
        let size = CGSize(width: 800, height: 600)
        XCTAssertTrue(MapDestinations.onAttribution(CGPoint(x: 40, y: 590), in: size))
        XCTAssertFalse(MapDestinations.onAttribution(CGPoint(x: 40, y: 500), in: size))
        XCTAssertFalse(MapDestinations.onAttribution(CGPoint(x: 400, y: 590), in: size))
    }

    /// A click on a pin chooses it; near a line, the place the line ends at; elsewhere, nothing.
    func testAClickChoosesThePinThenTheLineElseNothing() {
        let pins: [(key: String, at: CGPoint)] = [(key: "Toronto|Canada", at: CGPoint(x: 100, y: 100)), (key: "Paris|France", at: CGPoint(x: 400, y: 100))]
        let lines: [(key: String, points: [CGPoint])] = [(key: "Toronto|Canada", points: [CGPoint(x: 500, y: 300), CGPoint(x: 300, y: 200), CGPoint(x: 100, y: 100)]),
                                                         (key: "Paris|France", points: [CGPoint(x: 500, y: 300), CGPoint(x: 400, y: 100)])]
        XCTAssertEqual(MapDestinations.hit(CGPoint(x: 108, y: 104), pins: pins, lines: lines), "Toronto|Canada", "on the pin")
        XCTAssertEqual(MapDestinations.hit(CGPoint(x: 200, y: 154), pins: pins, lines: lines), "Toronto|Canada", "on the line's middle")
        XCTAssertEqual(MapDestinations.hit(CGPoint(x: 452, y: 200), pins: pins, lines: lines), "Paris|France")
        XCTAssertNil(MapDestinations.hit(CGPoint(x: 250, y: 300), pins: pins, lines: lines), "empty map")
        // Where a pin and another line meet, the pin wins.
        XCTAssertEqual(MapDestinations.hit(CGPoint(x: 402, y: 104), pins: pins, lines: lines + [(key: "Toronto|Canada", points: [CGPoint(x: 400, y: 0), CGPoint(x: 400, y: 200)])]), "Paris|France")
        XCTAssertEqual(MapDestinations.segmentDistance(CGPoint(x: 0, y: 5), CGPoint(x: -10, y: 0), CGPoint(x: 10, y: 0)), 5, accuracy: 0.001)
        XCTAssertEqual(MapDestinations.segmentDistance(CGPoint(x: 13, y: 4), CGPoint(x: -10, y: 0), CGPoint(x: 10, y: 0)), 5, accuracy: 0.001, "past the end")
        XCTAssertEqual(MapDestinations.segmentDistance(CGPoint(x: 3, y: 4), .zero, .zero), 5, accuracy: 0.001, "a line of one point")
    }
}
