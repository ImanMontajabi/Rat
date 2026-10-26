import XCTest
import RatFilterCore
import RatMonitor
@testable import Rat

/// Reverse DNS never holds up a pass (a dead DNS server used to stall the monitor for a minute per address), and
/// the Summary counts what the list's search and chips leave.
@MainActor
final class HostNamesAndSummaryTests: XCTestCase {
    /// A resolver that answers only when told to, and counts what it was asked.
    private final class SlowDNS: @unchecked Sendable {
        let lock = NSLock()
        var asked: [String] = []
        let answer = DispatchSemaphore(value: 0)
        var names: [String: String] = [:]
        func resolve(_ ip: String) -> String? {
            lock.withLock { asked.append(ip) }
            _ = answer.wait(timeout: .now() + 30)
            return lock.withLock { names[ip] }
        }
    }

    private func waitUntil(_ timeout: TimeInterval = 5, _ condition: () -> Bool) {
        let deadline = Date().addingTimeInterval(timeout)
        while !condition() && Date() < deadline { RunLoop.current.run(until: Date().addingTimeInterval(0.02)) }
    }

    // MARK: host names

    func testAddressesWithoutANetworkNameAreNeverLookedUp() {
        for ip in ["127.0.0.1", "127.8.9.10", "::1", "0.0.0.0", "::", "169.254.12.34", "fe80::1", "fe80::1c2b:3a4d%en0", "febf::1", "::ffff:127.0.0.1", "not an address"] {
            XCTAssertFalse(HostNames.hasNetworkName(ip), ip)
        }
        for ip in ["1.1.1.1", "203.0.113.9", "169.255.0.1", "2606:4700::1111", "fec0::1", "::2", "::ffff:8.8.8.8"] {
            XCTAssertTrue(HostNames.hasNetworkName(ip), ip)
        }
        let dns = SlowDNS()
        let names = HostNames(resolve: dns.resolve)
        for ip in ["127.0.0.1", "::1", "fe80::1%en0", "169.254.1.1", "0.0.0.0", "::"] {
            let r = names.lookup(ip)
            XCTAssertEqual(r.name, ip); XCTAssertTrue(r.settled, ip)
        }
        Thread.sleep(forTimeInterval: 0.2)
        XCTAssertEqual(dns.lock.withLock { dns.asked }, [], "no DNS query for loopback, unspecified or link-local")
    }

    func testALookupNeverWaitsForDNS() {
        let dns = SlowDNS()
        dns.names["203.0.113.9"] = "server.example.com"
        let names = HostNames(resolve: dns.resolve)
        let start = Date()
        let first = names.lookup("203.0.113.9", now: start)
        XCTAssertLessThan(Date().timeIntervalSince(start), 0.1, "answers at once while DNS hangs")
        XCTAssertEqual(first.name, "203.0.113.9"); XCTAssertFalse(first.settled)
        XCTAssertFalse(names.lookup("203.0.113.9", now: start.addingTimeInterval(1)).settled)
        XCTAssertTrue(names.lookup("203.0.113.9", now: start.addingTimeInterval(HostNames.grace)).settled, "judged by address after the grace period")
        waitUntil { dns.lock.withLock { dns.asked.count } == 1 }
        dns.answer.signal()
        waitUntil { names.lookup("203.0.113.9").name != "203.0.113.9" }
        XCTAssertEqual(names.lookup("203.0.113.9").name, "server.example.com")
        XCTAssertEqual(dns.lock.withLock { dns.asked }, ["203.0.113.9"], "one query per address")
    }

    private func ledger(_ names: HostNames) throws -> Ledger {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("rat-names-\(UUID())")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        addTeardownBlock { try? FileManager.default.removeItem(at: dir) }
        return Ledger(directory: dir, helperInstalled: false, names: names)
    }

    /// A pass with a hanging DNS server returns at once; the connection is judged when its name arrives, so a
    /// rule for its domain still matches.
    func testSlowDNSNeverHoldsUpAPassAndDomainRulesStillMatch() async throws {
        let dns = SlowDNS()
        dns.names["203.0.113.9"] = "tracker.example.com"
        let names = HostNames(resolve: dns.resolve)
        let l = try ledger(names)
        let app = "/Applications/Demo/Tool.app"
        l.rules.ruleSet.rules.append(Rule(verdict: .deny, processPath: app, remoteDomain: "example.com", profileID: l.rules.ruleSet.activeProfileID))
        let conns = [ObservedConnection(pid: 900, processPath: app + "/Contents/MacOS/Tool", proto: .tcp, remoteAddress: "203.0.113.9", remotePort: 443, localPort: 50100, tcpState: "ESTABLISHED"),
                     ObservedConnection(pid: 900, processPath: app + "/Contents/MacOS/Tool", proto: .tcp, remoteAddress: "::1", remotePort: 8080, localPort: 50101, tcpState: "ESTABLISHED")]
        let start = Date()
        await l.ingest(conns, [])
        XCTAssertLessThan(Date().timeIntervalSince(start), 1, "the pass does not wait for DNS")
        var row = try XCTUnwrap(l.apps.first { $0.id == app }?.remotes.first { $0.address == "203.0.113.9" })
        XCTAssertEqual(row.host, "203.0.113.9"); XCTAssertNil(row.verdict, "not judged before its name is known")
        XCTAssertEqual(l.deniedCount, 0)

        dns.answer.signal()
        waitUntil { names.lookup("203.0.113.9").name == "tracker.example.com" }
        await l.ingest(conns, [])
        row = try XCTUnwrap(l.apps.first { $0.id == app }?.remotes.first { $0.address == "203.0.113.9" })
        XCTAssertEqual(row.host, "tracker.example.com")
        XCTAssertEqual(row.verdict, .deny, "the domain rule matches once the name is in")
        XCTAssertEqual(l.deniedCount, 1)
        XCTAssertEqual(dns.lock.withLock { dns.asked }, ["203.0.113.9"], "::1 was never looked up")
    }

    // MARK: summary

    private func demo() throws -> Ledger {
        let l = try ledger(HostNames(resolve: { _ in nil }))
        l.installDemoData()
        return l
    }

    func testSummaryIsTheSessionsWithoutAFilter() throws {
        let l = try demo()
        let s = l.summary(MonitorFilter())
        XCTAssertFalse(s.filtered)
        XCTAssertEqual(s.apps.count, l.apps.count)
        XCTAssertEqual(s.bytesIn, l.sessionIn); XCTAssertEqual(s.bytesOut, l.sessionOut)
        XCTAssertEqual(s.unconfirmed, l.unconfirmedCount)
        XCTAssertEqual(l.domains(s.remotes).map(\.name), l.domains().map(\.name))
        XCTAssertFalse(l.summary(MonitorFilter(range: .hour)).filtered, "the time range alone is the chart's window")
    }

    func testSummaryFollowsTheRouteChipAndSearch() throws {
        let l = try demo()
        let proxy = l.summary(MonitorFilter(route: .proxy))
        XCTAssertTrue(proxy.filtered)
        XCTAssertEqual(proxy.apps.map(\.identity.name), ["Firefox"])
        XCTAssertEqual(proxy.remotes.count, 2, "the unmasked destination and the Tor connection")
        XCTAssertEqual(proxy.bytesIn, 3_000_000); XCTAssertEqual(proxy.bytesOut, 300_000)
        XCTAssertEqual(Set(l.domains(proxy.remotes).map(\.name)), ["example.org", "127.0.0.1"])
        XCTAssertEqual(l.countries(proxy.remotes).map(\.name), ["Spain"])

        let vpn = l.summary(MonitorFilter(search: "vpn"))
        XCTAssertEqual(vpn.apps.map(\.identity.name), ["Telegram"])
        XCTAssertEqual(vpn.remotes.map(\.host), ["demo3.example.com"], "only the tunnelled connection")
        XCTAssertEqual(l.countries(vpn.remotes).map(\.name), ["France"])

        let city = l.summary(MonitorFilter(search: "London"))
        XCTAssertEqual(city.topApps.map(\.identity.name), ["Google Chrome"])
        XCTAssertEqual(city.remotes.map(\.host), ["demo0.example.com"])
    }

    func testFilteredSummaryCountsVerdictsAndIncoming() throws {
        let l = try demo()
        guard let i = l.apps.firstIndex(where: { $0.identity.name == "Steam" }) else { return XCTFail("no Steam") }
        l.apps[i].remotes[0].verdict = .deny
        l.apps[i].remotes[1].verdict = .ask
        l.apps[i].listening = 2
        let s = l.summary(MonitorFilter(search: "steam"))
        XCTAssertEqual([s.denied, s.unconfirmed, s.incoming], [1, 1, 2])
    }
}
