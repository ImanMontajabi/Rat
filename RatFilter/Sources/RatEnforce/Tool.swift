import Darwin
import Foundation
import RatFilterCore
import RatMonitor

/// Entry point of the `rat-enforcerd` tool: `rat-enforcerd --denied <file> [--ports <file>] [--rules <file>] [--status <file>]
/// [--proxied <file> --owner-uid <uid>] [--repair <file>] [--blocklist <legacy file to delete>] [--anchor <name>]`.
/// `--rules` defaults to `deny-rules.json` next to the deny list, so the LaunchDaemon written by 1.4.0 needs no change.
public func runEnforcerTool(_ args: [String]) -> Never {
    func value(_ flag: String) -> String? { args.firstIndex(of: flag).flatMap { $0 + 1 < args.count ? args[$0 + 1] : nil } }
    // `--country <address> --geoip <file>`: the country a country rule would see for an address, read the way the
    // daemon reads it (`GeoFile`), for scripts/verify-blocking.sh. Prints the code, or "-" when there is none.
    if let address = value("--country"), let file = value("--geoip") {
        guard let db = GeoFile.open(file, ownerUID: getuid()) else {
            FileHandle.standardError.write(Data("cannot read \(file)\n".utf8)); exit(66)
        }
        print(db.countryCode(address) ?? "-")
        exit(0)
    }
    // `--tunnels --geoip <file>`: where each VPN tunnel leads, found the way the daemon finds it (its client's, else its
    // relays', outside connections, or for a WireGuard client the servers the routing table pins outside), one line
    // per tunnel: "<interface> <country or -> <carrier addresses…>", then with `--verbose` the client and its relays
    // ("owner <pid> <path>", "relay <pid> <path>") and the host routes ("pinned <address> <interface>").
    if args.contains("--tunnels"), let file = value("--geoip") {
        guard let db = GeoFile.open(file, ownerUID: getuid()) else {
            FileHandle.standardError.write(Data("cannot read \(file)\n".utf8)); exit(66)
        }
        let tunnels = NetworkRoutes.tunnelAddresses()
        let owners = NetworkRoutes.tunnelOwnerProcesses(relays: true)
        for iface in Set(tunnels.values).sorted() {
            let servers = owners[iface].map { o in
                NetworkRoutes.carrierServers(owner: ConnectionSampler.connections(of: o.pid), relays: o.relays.flatMap(ConnectionSampler.connections(of:)),
                                             tunnels: tunnels, isLocal: { LocalNetwork.contains($0) },
                                             pinned: { NetworkRoutes.pinnedServers(for: iface, isLocal: { LocalNetwork.contains($0) }) })
            } ?? []
            print(([iface, NetworkRoutes.serverCountry(servers, lookup: db.countryCode) ?? "-"] + servers).joined(separator: " "))
            if args.contains("--verbose") {
                if let o = owners[iface] {
                    print("  owner \(o.pid) \(o.path)")
                    for r in o.relays { print("  relay \(r) \(ConnectionSampler.path(of: r))") }
                } else { print("  owner unknown") }
            }
        }
        if args.contains("--verbose") {
            for r in NetworkRoutes.hostRoutes() { print("pinned \(r.destination) \(r.interface)") }
        }
        exit(0)
    }
    guard let denied = value("--denied") else {
        FileHandle.standardError.write(Data("usage: rat-enforcerd --denied <file> [--ports <file>] [--rules <file>] [--status <file>] [--proxied <file> --owner-uid <uid>] [--anchor <name>]\n       rat-enforcerd --country <address> --geoip <file.mmdb>\n       rat-enforcerd --tunnels --geoip <file.mmdb>\n".utf8))
        exit(64)
    }
    var s = EnforcerDaemon.Settings(deniedFile: denied, portsFile: value("--ports"), legacyBlocklistFile: value("--blocklist"),
                                           statusFile: value("--status"))
    if let a = value("--anchor") { s.anchor = a }
    s.proxiedFile = value("--proxied")
    s.ownerUID = value("--owner-uid").flatMap { uid_t($0) }
    s.repairFile = value("--repair")
    s.rulesFile = value("--rules") ?? ((denied as NSString).deletingLastPathComponent as NSString).appendingPathComponent("deny-rules.json")
    let daemon = EnforcerDaemon(settings: s)
    daemon.start()
    var sources: [DispatchSourceSignal] = []
    for sig in [SIGTERM, SIGINT] {
        signal(sig, SIG_IGN)
        let src = DispatchSource.makeSignalSource(signal: sig, queue: .main)
        src.setEventHandler { daemon.stop(); exit(0) }
        src.resume()
        sources.append(src)
    }
    Thread.detachNewThread { daemon.loop() }
    dispatchMain()
}
