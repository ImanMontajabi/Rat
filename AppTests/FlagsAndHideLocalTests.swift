import XCTest
import RatMonitor
@testable import Rat

/// Country flags next to places, and Hide Local: connections that stay near this Mac, and apps and processes that
/// have only those, leave the list, the map and the Summary.
@MainActor
final class FlagsAndHideLocalTests: XCTestCase {
    func testFlagsFromCountryCodes() {
        XCTAssertEqual(Flag.emoji("DE"), "🇩🇪")
        XCTAssertEqual(Flag.emoji("us"), "🇺🇸", "case does not matter")
        XCTAssertEqual(Flag.emoji("NL"), "🇳🇱")
        XCTAssertEqual(Flag.emoji("CA"), "🇨🇦")
        XCTAssertEqual(Flag.emoji("EU"), "🇪🇺", "the databases use EU for some European ranges")
        for bad in ["", "D", "DEU", "ZZ", "XX", "12", "D1", "🇩🇪"] { XCTAssertEqual(Flag.emoji(bad), "", bad) }
    }

    func testAPlaceReadsFlagCityCountry() {
        let berlin = GeoPoint(coordinate: .init(latitude: 52.52, longitude: 13.4), city: "Berlin", country: "Germany", countryCode: "DE")
        XCTAssertEqual(berlin.place, "🇩🇪 Berlin, Germany")
        XCTAssertEqual(GeoPoint(coordinate: .init(), city: "", country: "Germany", countryCode: "DE").place, "🇩🇪 Germany")
        XCTAssertEqual(GeoPoint(coordinate: .init(), city: "Paris", country: "France").place, "Paris, France", "no code, no flag")
    }

    /// The real City database gives a code with each country (the bundled one; skipped where it is not fetched).
    func testTheDatabaseGivesCountryCodes() throws {
        let geo = GeoService()
        try XCTSkipUnless(geo.available, "no GeoIP database here")
        let point = try XCTUnwrap(geo.lookup("1.1.1.1"))
        XCTAssertEqual(point.countryCode.count, 2, "\(point)")
        XCTAssertFalse(point.flag.isEmpty, "\(point)")
    }

    func testWhatIsLocalTraffic() {
        for a in ["127.0.0.1", "::1", "169.254.10.1", "fe80::1", "10.1.2.3", "172.16.0.1", "172.31.255.1", "192.168.1.20", "fd12::1",
                  "224.0.0.251", "ff02::fb", "239.255.255.250", "255.255.255.255"] {
            XCTAssertTrue(isLocalTraffic(address: a, proto: "TCP", port: 443), a)
        }
        for a in ["8.8.8.8", "172.32.0.1", "2001:db8::1", "203.0.113.5", "100.64.0.1"] { XCTAssertFalse(isLocalTraffic(address: a, proto: "TCP", port: 443), a) }
        XCTAssertTrue(isLocalTraffic(address: "203.0.113.5", proto: "UDP", port: 5353), "mDNS, whatever its address")
        XCTAssertFalse(isLocalTraffic(address: "203.0.113.5", proto: "TCP", port: 5353))
    }

    func testAProxiedLoopbackConnectionLeavesTheMac() {
        let tor = RemoteHost(address: "127.0.0.1", host: "127.0.0.1", port: 9050, proto: "TCP", route: .localProxy(program: "Tor", listener: "127.0.0.1:9050"))
        XCTAssertFalse(tor.isLocal, "it goes out through Tor")
        XCTAssertTrue(RemoteHost(address: "127.0.0.1", host: "127.0.0.1", port: 8080, proto: "TCP").isLocal)
    }

    private func ledger() throws -> Ledger {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("rat-hidelocal-\(UUID())")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        addTeardownBlock { try? FileManager.default.removeItem(at: dir) }
        return Ledger(directory: dir, helperInstalled: false, names: HostNames(resolve: { _ in nil }))
    }

    private func conn(_ pid: Int32, _ path: String, _ address: String, _ port: Int, local: Int) -> ObservedConnection {
        ObservedConnection(pid: pid, processPath: path, proto: .tcp, remoteAddress: address, remotePort: port, localPort: local, tcpState: "ESTABLISHED")
    }

    func testHideLocalHidesLocalConnectionsAndAppsWithOnlyThose() async throws {
        let l = try ledger()
        let printer = "/Applications/Printer.app", browser = "/Applications/Browser.app"
        await l.ingest([conn(10, printer + "/Contents/MacOS/Printer", "192.168.1.20", 631, local: 50000),
                        conn(20, browser + "/Contents/MacOS/Browser", "192.168.1.20", 8009, local: 50001),
                        conn(20, browser + "/Contents/MacOS/Browser", "203.0.113.9", 443, local: 50002)], [])
        let settings = AppSettings.shared
        let wasLocal = settings.includeLocalNetwork
        settings.includeLocalNetwork = true   // the older setting would hide the printer for having no traffic
        defer { settings.includeLocalNetwork = wasLocal }

        var filter = MonitorFilter()
        XCTAssertEqual(Set(filter.apps(l, settings: settings).map(\.id)), [printer, browser])
        filter.hideLocal = true
        XCTAssertEqual(filter.apps(l, settings: settings).map(\.id), [browser], "an app with only local connections is hidden")
        let b = try XCTUnwrap(l.apps.first { $0.id == browser })
        XCTAssertEqual(b.remotes.filter { filter.matches($0, of: b) }.map(\.address), ["203.0.113.9"], "the map draws only the outside connection")
        XCTAssertFalse(filter.isActive, "a standing preference, not a filter")

        let s = l.summary(filter, settings: settings)
        XCTAssertFalse(s.filtered)
        XCTAssertEqual(s.remotes.map(\.address), ["203.0.113.9"])
        XCTAssertEqual(s.apps.map(\.id), [browser])
        XCTAssertEqual(l.summary(MonitorFilter(), settings: settings).remotes.count, 3, "without it everything counts")
    }

    func testTheChipIsRemembered() {
        let s = AppSettings.shared
        let was = s.hideLocal
        defer { s.hideLocal = was }
        s.hideLocal = true
        XCTAssertTrue(Preferences.store.bool(forKey: "hideLocal"))
        s.hideLocal = false
        XCTAssertFalse(Preferences.store.bool(forKey: "hideLocal"))
        XCTAssertNotIdentical(Preferences.store, UserDefaults.standard, "tests never write the real preferences")
    }
}
