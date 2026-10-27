import Darwin
import Foundation

/// Entry point of the `rat-enforcerd` tool: `rat-enforcerd --denied <file> [--ports <file>] [--rules <file>] [--status <file>]
/// [--proxied <file> --owner-uid <uid>] [--repair <file>] [--blocklist <legacy file to delete>] [--anchor <name>]`.
/// `--rules` defaults to `deny-rules.json` next to the deny list, so the LaunchDaemon written by 1.4.0 needs no change.
public func runEnforcerTool(_ args: [String]) -> Never {
    func value(_ flag: String) -> String? { args.firstIndex(of: flag).flatMap { $0 + 1 < args.count ? args[$0 + 1] : nil } }
    guard let denied = value("--denied") else {
        FileHandle.standardError.write(Data("usage: rat-enforcerd --denied <file> [--ports <file>] [--rules <file>] [--status <file>] [--proxied <file> --owner-uid <uid>] [--anchor <name>]\n".utf8))
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
