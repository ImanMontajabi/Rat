import Darwin
import Foundation
import RatFilterCore
import RatMonitor

/// Runs a command; returns its exit status. Injectable so tests never touch the firewall.
public typealias CommandRunner = (_ executable: String, _ arguments: [String], _ stdin: String?) -> Int32

public func runCommand(_ executable: String, _ arguments: [String], _ stdin: String?) -> Int32 {
    // The daemon's threads have no pool that is drained: without this one each call's pipe stays open (see
    // `captureCommand`).
    autoreleasepool { runCommandOnce(executable, arguments, stdin) }
}

private func runCommandOnce(_ executable: String, _ arguments: [String], _ stdin: String?) -> Int32 {
    let p = Process()
    p.executableURL = URL(fileURLWithPath: executable)
    p.arguments = arguments
    p.standardOutput = FileHandle.nullDevice
    p.standardError = FileHandle.nullDevice
    let pipe = Pipe()
    if stdin != nil { p.standardInput = pipe }
    do { try p.run() } catch { return -1 }
    if let stdin {
        pipe.fileHandleForWriting.write(Data(stdin.utf8))
        try? pipe.fileHandleForWriting.close()
    }
    p.waitUntilExit()
    return p.terminationStatus
}

/// Runs a command and returns its standard output (for `pfctl -s …`). Injectable like `CommandRunner`.
public typealias CommandCapture = (_ executable: String, _ arguments: [String]) -> String

public func captureCommand(_ executable: String, _ arguments: [String]) -> String {
    // Foundation autoreleases the pipe's file handle. The daemon's loop runs on a thread whose pool is never drained,
    // so without a pool here every call kept one descriptor open: after a few hundred `pfctl` runs the daemon hit
    // launchd's limit of 256, could not start pfctl any more and stopped enforcing.
    autoreleasepool { captureCommandOnce(executable, arguments) }
}

private func captureCommandOnce(_ executable: String, _ arguments: [String]) -> String {
    let p = Process()
    p.executableURL = URL(fileURLWithPath: executable)
    p.arguments = arguments
    let out = Pipe()
    p.standardOutput = out
    p.standardError = out
    do { try p.run() } catch { return "" }
    let data = out.fileHandleForReading.readDataToEndOfFile()
    p.waitUntilExit()
    return String(decoding: data, as: UTF8.self)
}

/// What the daemon is doing, published for Rat (which runs as the user) in a world-readable file.
public struct EnforcerStatus: Codable, Equatable {
    public struct App: Codable, Equatable {
        public var processes: Int
        public var ports: Int
        public init(processes: Int, ports: Int) { self.processes = processes; self.ports = ports }
    }
    public var pid: Int32
    public var updated: Date
    public var pfEnabled: Bool
    /// The main ruleset evaluates `com.apple/*` anchors, so the rules in ours are seen at all.
    public var anchorHooked: Bool
    public var deniedApps: [String: App]
    public var blockedPorts: Int
    /// Apps with sockets the rules in `deny-rules.json` deny (one process, one connection), by the app's rule key:
    /// the processes holding such sockets and their ports (nil from daemons before 1.5.0).
    public var ruleDenied: [String: App]?
    /// How many deny rules the daemon follows itself (nil from daemons before 1.5.0).
    public var denyRules: Int?
    /// Loopback connections of denied apps to other apps' ports (local proxies, SSH forwards) blocked on lo0.
    public var blockedLoopbackPorts: Int?
    /// Whether the daemon reads proxy requests on lo0 (nil from daemons before 1.1.0).
    public var proxyCapture: Bool?
    /// VPN tunnel interface → path of the process that opened it (root sees VPN daemons Rat cannot; 1.2.0).
    public var tunnels: [String: String]?
    /// Why pf could not be put right automatically (see `PFHeal`); nil when it runs and evaluates our anchor (1.4.0).
    public var pfIssue: String?
    /// How often the daemon turned pf on again or restored the anchors since it started, and the last time.
    public var repairs: Int?
    public var lastRepair: String?
    public var lastRepairAt: Date?
    /// SHA-256 of the daemon's executable when it started, so Rat can tell that the running helper is not the one in
    /// its bundle (nil from daemons before 1.4.0).
    public var executableSHA256: String?

    public init(pid: Int32, updated: Date, pfEnabled: Bool, anchorHooked: Bool, deniedApps: [String: App], blockedPorts: Int,
                ruleDenied: [String: App]? = nil, denyRules: Int? = nil, blockedLoopbackPorts: Int? = nil, proxyCapture: Bool? = nil, tunnels: [String: String]? = nil,
                pfIssue: String? = nil, repairs: Int? = nil, lastRepair: String? = nil, lastRepairAt: Date? = nil,
                executableSHA256: String? = nil) {
        self.pid = pid; self.updated = updated; self.pfEnabled = pfEnabled; self.anchorHooked = anchorHooked
        self.deniedApps = deniedApps; self.blockedPorts = blockedPorts; self.ruleDenied = ruleDenied; self.denyRules = denyRules
        self.blockedLoopbackPorts = blockedLoopbackPorts; self.proxyCapture = proxyCapture; self.tunnels = tunnels
        self.pfIssue = pfIssue; self.repairs = repairs; self.lastRepair = lastRepair; self.lastRepairAt = lastRepairAt
        self.executableSHA256 = executableSHA256
    }
}

/// Root daemon. For every process that belongs to a denied app it reads all sockets on every pass (every 3 ms while
/// such a process runs) and loads their local ports into the pf anchor, so connections to servers Rat has never
/// seen (CDN rotation, IPv6 fallback, QUIC migration) are cut as well. Only ports are ever blocked, never remote
/// addresses. Loopback connections of denied processes to another app's port (a local proxy, an `ssh -L` forward)
/// are blocked on lo0, so a denied app cannot leave the Mac through a tunnel either.
///
/// Rules for one process of an app or one connection (`deny-rules.json`, see `DaemonRules`) are followed the same
/// way: every process a deny rule names is read on every pass, and the local ports of the sockets the rules deny
/// (`SocketJudge`) are blocked, so they are cut during the handshake instead of after Rat's next 1.5 s pass.
public final class EnforcerDaemon {
    public struct Settings {
        public var deniedFile: String
        /// Local ports of sockets that rules deny (written by Rat each pass); optional.
        public var portsFile: String?
        /// The rules for one process or connection that the daemon follows itself (`DaemonRules`, written by Rat);
        /// optional. `rat-enforcerd` reads `deny-rules.json` next to the deny list unless told otherwise.
        public var rulesFile: String?
        /// Older versions kept a list of server addresses here. It is deleted: addresses are never blocked.
        public var legacyBlocklistFile: String?
        /// Where the daemon publishes `EnforcerStatus` as JSON; optional.
        public var statusFile: String?
        /// Where proxied connections of `ownerUID`'s processes are published (see `ProxyWatch`); optional.
        public var proxiedFile: String?
        public var ownerUID: uid_t?
        public var anchor = "com.apple/rat"
        /// Pass interval while a denied or watched process runs. Every pass reads the newest processes and every
        /// socket of every denied or watched process (reading Chrome's ~30 processes takes about 0.05 ms).
        public var interval: TimeInterval = 0.003
        /// Pass interval while something is denied but none of it runs: how soon a denied program that starts is
        /// seen (about 3 % CPU at 20 ms, against 8 % at 3 ms).
        public var standbyInterval: TimeInterval = 0.02
        public var idleInterval: TimeInterval = 0.25
        /// Ports stay blocked this long after their socket disappears, to cover packets still in flight.
        public var portHold: TimeInterval = 5
        /// How often pf is checked to still run and evaluate our anchor (a VPN client may stop it or replace the
        /// main ruleset) and put right (`PFHeal`).
        public var watchdogInterval: TimeInterval = 2
        /// Rat touches this file (in the user's data folder) for Settings > Security's Repair Firewall; only its
        /// modification time is read. Optional.
        public var repairFile: String?
        /// The system's pf configuration, loaded again when pf was turned off with another program's rules in it.
        public var systemConfig = "/etc/pf.conf"
        public init(deniedFile: String, portsFile: String? = nil, legacyBlocklistFile: String? = nil, statusFile: String? = nil) {
            self.deniedFile = deniedFile; self.portsFile = portsFile; self.legacyBlocklistFile = legacyBlocklistFile; self.statusFile = statusFile
        }
    }

    private let settings: Settings
    private let run: CommandRunner
    private let capture: CommandCapture
    private let background = DispatchQueue(label: "rat.enforcer.background", qos: .utility)
    private var denied = DeniedApps(text: "")
    private var deniedStamp: Date?
    private var filePorts: [Int] = []
    private var portsStamp: Date?
    private var rulesStamp: Date?
    /// Judges sockets by the rules in `rulesFile`; nil when no rule denies a process path.
    private var judge: SocketJudge?
    private var denyRuleCount = 0
    /// pid -> (app, executable) of a process a deny rule may concern; nil = classified, not watched.
    private var watched: [pid_t: Watched?] = [:]
    struct Watched { var app: String; var executable: String }
    /// Socket -> whether the rules deny it, kept for the sockets seen on the last pass (cleared when the rules change).
    private var socketVerdicts: [SocketKey: Bool] = [:]
    struct SocketKey: Hashable { var pid: pid_t; var proto: UInt8; var localPort: Int; var remotePort: Int; var remote: String }
    private var portsByRuleApp: [String: (processes: Int, ports: Set<Int>)] = [:]
    /// pid -> the denied entry it belongs to ("" = not denied).
    private var verdictCache: [pid_t: String] = [:]
    private var firstSeen: [pid_t: Date] = [:]
    /// Start times read so far (tests check none is read before a pass loads its ports).
    private(set) var agesRead = 0
    private var lastCleanup = Date.distantPast
    /// Processes first seen less than a second ago and not denied: their path is read again every pass (see `tick`).
    private var young: [pid_t] = []
    /// The watched processes, as `watched` holds them (rebuilt when it changes, not on every pass).
    private var ruledList: [(pid_t, Watched)] = []
    private var watchedChanged = false
    private var newest = [pid_t](repeating: 0, count: 32)
    /// Whether the last pass found a denied or watched process (see `tick`).
    public private(set) var watching = false
    public private(set) var deniedPIDs = Set<pid_t>()
    private var portsByApp: [String: (processes: Int, ports: Set<Int>)] = [:]
    public private(set) var lastTickDuration: TimeInterval = 0
    private var portSeen: [Int: Date] = [:]
    private var loopbackSeen: [Int: Date] = [:]
    private var fileLoopbackPorts: [Int] = []
    public private(set) var loadedPorts: [Int] = []
    public private(set) var loadedLoopbackPorts: [Int] = []
    public private(set) var proxyWatch: ProxyWatch?
    private var loaded = false
    private var token: String?
    private var lastWatchdog = Date.distantPast
    private var lastStatus = Date.distantPast
    private var pfEnabled = false
    private var anchorHooked = false
    private var pfIssue: String?
    private var repairs = 0
    private var recentRepairs: [Date] = []
    private var lastRepair: String?
    private var lastRepairAt: Date?
    private var repairStamp: Date?
    private var executableSHA256: String?
    private var lastTunnelScan = Date.distantPast
    private let tunnelLock = NSLock()
    private var tunnels: [String: String] = [:]
    public private(set) var reloads = 0
    private let trace = !(ProcessInfo.processInfo.environment["RAT_TRACE"] ?? "").isEmpty
    private var traceTicks = 0, traceTime = 0.0

    public init(settings: Settings, run: @escaping CommandRunner = runCommand, capture: @escaping CommandCapture = captureCommand) {
        self.settings = settings
        self.run = run
        self.capture = capture
    }

    public func start() {
        // Read once: an update replaces the file on disk while this process keeps running the old code.
        executableSHA256 = FileDigest.sha256(atPath: ConnectionSampler.path(of: getpid()))
        // A repair asked for before this start is not replayed.
        repairStamp = settings.repairFile.flatMap(Self.modified)
        watchdog(now: Date())
        // Our reference keeps pf on while we run, even when another program releases its own (released in `stop`).
        // Taken only once pf runs: turning it on with another program's leftover rules is `heal`'s decision.
        if token == nil, pfEnabled { enablePF() }
        // Start clean: whatever an earlier version left in the anchor (address tables, old ports) is removed.
        _ = run("/sbin/pfctl", ["-a", settings.anchor, "-F", "all"], nil)
        if let legacy = settings.legacyBlocklistFile { try? FileManager.default.removeItem(atPath: legacy) }
        loadedPorts = []
        loadedLoopbackPorts = []
        loaded = true
        if let file = settings.proxiedFile, let owner = settings.ownerUID {
            let w = ProxyWatch(settings: .init(file: file, ownerUID: owner))
            w.removeFile()
            if w.start() { proxyWatch = w }
        }
    }

    public func stop() {
        _ = run("/sbin/pfctl", ["-a", settings.anchor, "-F", "all"], nil)
        if let token { _ = run("/sbin/pfctl", ["-X", token], nil) }
        if let f = settings.statusFile { try? FileManager.default.removeItem(atPath: f) }
        proxyWatch?.removeFile()
    }

    /// Takes a reference on pf so it is enabled while we run (released in `stop`).
    private func enablePF() {
        let text = capture("/sbin/pfctl", ["-E"])
        if let t = text.components(separatedBy: "Token : ").dropFirst().first?.split(whereSeparator: \.isNewline).first {
            token = String(t)
        }
    }

    public func loop() {
        // A change to a file Rat hands over ends the sleep at once: a deny made while nothing was denied waited for
        // the idle sleep (up to 0.25 s) before.
        let wake = FileWake(files: [settings.deniedFile, settings.portsFile, settings.rulesFile, settings.repairFile].compactMap { $0 })
        while true {
            let busy = autoreleasepool { tick() }
            if trace, busy, watching { traceTicks += 1; traceTime += lastTickDuration; if traceTicks == 400 { FileHandle.standardError.write(Data("avg tick \(Int(traceTime / 400 * 1e6)) us, reloads \(reloads)\n".utf8)); traceTicks = 0; traceTime = 0 } }
            if wake.wait(!busy ? settings.idleInterval : watching ? settings.interval : settings.standbyInterval) { filesChanged() }
        }
    }

    /// A file Rat hands over changed: the next pass reads it, whenever the last check was.
    public func filesChanged() { lastFileCheck = .distantPast }

    /// One pass. Returns whether there is anything to enforce (a denied app or a deny rule for a process); `watching`
    /// says whether one of its processes runs. The loop then passes every `interval`, every `standbyInterval` while
    /// none runs, and every `idleInterval` with nothing to enforce.
    @discardableResult
    public func tick(now: Date = Date()) -> Bool {
        let began = Date()
        defer { lastTickDuration = Date().timeIntervalSince(began) }
        refreshFiles(now: now)
        watchdog(now: now)
        defer { publishStatus(now: now) }
        let judge = self.judge
        guard !denied.isEmpty || judge != nil else {
            verdictCache.removeAll(); deniedPIDs.removeAll(); portsByApp.removeAll()
            watched.removeAll(); socketVerdicts.removeAll(); portsByRuleApp.removeAll()
            young.removeAll(); ruledList.removeAll(); lastCleanup = .distantPast; watching = false
            settle(now: now, live: [], loopback: [])
            return false
        }
        // Listing every process costs more than the rest of a pass, and at 300 passes a second it was most of the
        // helper's CPU. A new process is listed first, so the newest few show whether one started; every process is
        // listed then, and four times a second anyway (which also forgets the processes that exited).
        let full = now.timeIntervalSince(lastCleanup) >= 0.25 || startedProcess()
        let pids = full ? ConnectionSampler.allPIDs() : young
        if full { young = [] }
        // A process's age is the kernel's (`startTime`): counted from when the daemon met it, every process was
        // young for a second at the daemon's start and after each deny-list change, which kept a core busy for two
        // seconds. Reading it costs about 15 µs a process, 15 ms for a whole Mac, so it is read at the end of the
        // pass, once pf has this pass's ports: the pass right after a deny loads the denied process's ports as soon
        // as before. Until then a process met for the first time counts as young.
        var unaged: [pid_t] = []
        defer {
            for pid in unaged { firstSeen[pid] = ConnectionSampler.startTime(of: pid) ?? now }
            agesRead += unaged.count
            if !unaged.isEmpty { young = young.filter { verdictCache[$0] == "" && now.timeIntervalSince(firstSeen[$0] ?? now) < 1 } }
        }
        for pid in pids {
            let known = verdictCache[pid]
            if known == nil { firstSeen[pid] = nil; unaged.append(pid) }
            // A new process is first a fork of its parent (a shell) and only then the program: until it is a second
            // old, its path is read again every pass so the exec is noticed.
            guard known == nil || (known == "" && now.timeIntervalSince(firstSeen[pid] ?? now) < 1) else { continue }
            if full, known == nil || known == "" { young.append(pid) }
            let path = ConnectionSampler.path(of: pid)
            // A young process that exited is left as it was until the cleanup forgets it, as when every process was
            // listed on every pass: marking it unwatched at once dropped the daemon to its idle rate between two
            // short-lived processes, so the next one was seen up to 0.25 s late.
            if !full, path.hasPrefix("pid ") { continue }
            var responsible: String??
            let responsiblePath = { () -> String? in
                if let r = responsible { return r }
                let r = ProcessGrouping.responsiblePath(of: pid); responsible = .some(r); return r
            }
            let entry = path.hasPrefix("pid ") ? nil : denied.entry(for: path, responsiblePath: responsiblePath)
            verdictCache[pid] = entry ?? ""
            if entry != nil {
                deniedPIDs.insert(pid)
                setWatched(pid, nil)
                if trace { FileHandle.standardError.write(Data("denied pid \(pid) (\(entry!))\n".utf8)) }
            } else if let judge, !path.hasPrefix("pid ") {
                // The app as Rat's list groups it, so a rule for the app or for one of its processes matches here too.
                let app = ProcessGrouping.owner(of: path, responsiblePath: responsiblePath).ruleKey
                setWatched(pid, judge.watches(app: app, executable: path) ? Watched(app: app, executable: path) : nil)
            } else {
                setWatched(pid, nil)
            }
        }
        // Forgetting processes that exited is the costly part (hundreds of entries), so it runs a few times a second;
        // reading the sockets of a process that just exited returns nothing in the meantime.
        young = young.filter { verdictCache[$0] == "" && now.timeIntervalSince(firstSeen[$0] ?? now) < 1 }
        if full, now.timeIntervalSince(lastCleanup) >= 0.25 {
            lastCleanup = now
            let current = Set(pids)
            verdictCache = verdictCache.filter { current.contains($0.key) }
            firstSeen = firstSeen.filter { current.contains($0.key) }
            deniedPIDs = deniedPIDs.filter { current.contains($0) }
            let before = watched.count
            watched = watched.filter { current.contains($0.key) }
            if watched.count != before { watchedChanged = true }
        }
        if watchedChanged {
            watchedChanged = false
            ruledList = watched.compactMap { pid, w in w.map { (pid, $0) } }
        }
        let ruled = judge == nil ? [] : ruledList
        // Nothing it names runs: the next pass comes after `standbyInterval`, not the 0.25 s idle sleep, so a denied
        // program that starts is cut within about 20 ms. A process is first seen before its `exec`, as its parent's
        // program, so the passes that follow are what notice it became the denied one.
        watching = !deniedPIDs.isEmpty || !ruled.isEmpty
        guard watching else {
            portsByApp.removeAll(); portsByRuleApp.removeAll(); socketVerdicts.removeAll()
            settle(now: now, live: [], loopback: []); return true
        }

        // Every socket of every denied process, every pass: descriptors are reused and a socket gets its port only
        // when it connects, so nothing read earlier can be trusted.
        var ports = Set<Int>()
        var byApp: [String: (processes: Int, ports: Set<Int>)] = [:]
        var listening: [String: Set<Int>] = [:]
        var loopbackSockets: [(entry: String, local: Int, remote: Int)] = []
        for pid in deniedPIDs {
            let entry = verdictCache[pid] ?? ""
            var app = byApp[entry] ?? (0, [])
            app.processes += 1
            for fd in ConnectionSampler.socketFDs(of: pid) {
                guard let c = ConnectionSampler.connection(pid: pid, fd: fd, processPath: ""), c.localPort != 0 else { continue }
                if c.tcpState == "LISTEN" { listening[entry, default: []].insert(c.localPort); continue }
                ports.insert(c.localPort)
                app.ports.insert(c.localPort)
                if c.proto == .tcp, ProxyWatch.isLoopback(c.remoteAddress) { loopbackSockets.append((entry, c.localPort, c.remotePort)) }
            }
            byApp[entry] = app
        }
        portsByApp = byApp

        // The sockets of processes a deny rule names, judged like Rat's pass judges their connections. A socket's
        // verdict is kept while it exists, so each one is judged once (again only when the rules or names change).
        var verdicts: [SocketKey: Bool] = [:]
        var byRuleApp: [String: (processes: Int, ports: Set<Int>)] = [:]
        if let judge {
            for (pid, w) in ruled {
                var cut = Set<Int>()
                for fd in ConnectionSampler.socketFDs(of: pid) {
                    guard let c = ConnectionSampler.connection(pid: pid, fd: fd, processPath: ""), c.localPort != 0, c.tcpState != "LISTEN",
                          !ProxyWatch.isLoopback(c.remoteAddress) else { continue }
                    let key = SocketKey(pid: pid, proto: c.proto == .udp ? 17 : 6, localPort: c.localPort, remotePort: c.remotePort, remote: c.remoteAddress)
                    let deny = socketVerdicts[key] ?? judge.denies(app: w.app, executable: w.executable, address: c.remoteAddress,
                                                                    port: c.remotePort, proto: c.proto == .udp ? .udp : .tcp)
                    verdicts[key] = deny
                    if deny { cut.insert(c.localPort) }
                }
                guard !cut.isEmpty else { continue }
                ports.formUnion(cut)
                var app = byRuleApp[w.app] ?? (0, [])
                app.processes += 1
                app.ports.formUnion(cut)
                byRuleApp[w.app] = app
            }
        }
        socketVerdicts = verdicts
        portsByRuleApp = byRuleApp
        settle(now: now, live: ports, loopback: Self.loopbackPortsToBlock(loopbackSockets, listening: listening))
        return true
    }

    /// Whether one of the newest processes is not known yet.
    private func startedProcess() -> Bool {
        let n = ConnectionSampler.newestPIDs(into: &newest)
        for i in 0..<n where newest[i] > 0 && verdictCache[newest[i]] == nil { return true }
        return false
    }

    private func setWatched(_ pid: pid_t, _ w: Watched?) {
        let old = watched[pid]
        watched[pid] = .some(w)
        // Only a watched process entering or leaving changes the list the pass reads.
        if w != nil || (old ?? nil) != nil { watchedChanged = true }
    }

    /// The loopback connections a denied app opened to another program (a local proxy, an `ssh -L` forward, any
    /// local server): their local ports. Connections between the app's own processes, and connections other
    /// programs opened to a port the app listens on, are left alone.
    static func loopbackPortsToBlock(_ sockets: [(entry: String, local: Int, remote: Int)], listening: [String: Set<Int>]) -> Set<Int> {
        var out = Set<Int>()
        for s in sockets {
            let own = listening[s.entry] ?? []
            if own.contains(s.local) || own.contains(s.remote) { continue }
            out.insert(s.local)
        }
        return out
    }

    /// Loads the ports if they changed.
    private func settle(now: Date, live ports: Set<Int>, loopback: Set<Int>) {
        // Ports named by Rat (sockets a rule denies) count while the file is fresh: Rat rewrites it every pass,
        // so a crashed Rat cannot leave ports blocked for good.
        let fresh = portsStamp.map { now.timeIntervalSince($0) < 10 } ?? false
        for p in ports.union(fresh ? filePorts : []) { portSeen[p] = now }
        for p in loopback.union(fresh ? fileLoopbackPorts : []) { loopbackSeen[p] = now }
        portSeen = portSeen.filter { now.timeIntervalSince($0.value) < settings.portHold }
        loopbackSeen = loopbackSeen.filter { now.timeIntervalSince($0.value) < settings.portHold }
        let held = portSeen.keys.sorted(), heldLoopback = loopbackSeen.keys.sorted()
        if held != loadedPorts || heldLoopback != loadedLoopbackPorts || !loaded {
            let added = Set(held).subtracting(loadedPorts)
            apply(ports: held, loopback: heldLoopback)
            // Loopback states are not killed: pfctl can only kill by address pair, and 127.0.0.1 <-> 127.0.0.1
            // would be every local connection on the Mac. Rat's rules keep no state, so none exists by default.
            if !added.isEmpty { killStates(localPorts: added) }
        }
    }

    private func apply(ports: [Int], loopback: [Int]) {
        let rules = PFRules.render(ports: ports, loopbackPorts: loopback)
        let t0 = Date()
        defer { if trace { FileHandle.standardError.write(Data("apply \(ports.count) ports in \(Int(Date().timeIntervalSince(t0) * 1000)) ms\n".utf8)) } }
        if rules.isEmpty { _ = run("/sbin/pfctl", ["-a", settings.anchor, "-F", "all"], nil) }
        else { _ = run("/sbin/pfctl", ["-a", settings.anchor, "-f", "-"], rules) }
        loadedPorts = ports
        loadedLoopbackPorts = loopback
        loaded = true
        reloads += 1
    }

    /// pf looks up its state table before any rule. Rat's rules create no state, but another ruleset with
    /// `keep state` could hold one for a connection that is now denied; such a state is killed (between this Mac's
    /// address and that server, the narrowest kill macOS' pfctl offers). Runs off the watch loop.
    private func killStates(localPorts: Set<Int>) {
        let capture = self.capture, run = self.run
        background.async {
            let pairs = PFStates.pairs(in: capture("/sbin/pfctl", ["-s", "states"]), localPorts: localPorts)
            for (local, remote) in pairs { _ = run("/sbin/pfctl", ["-k", local, "-k", remote], nil) }
        }
    }

    /// pf must keep running and evaluating our anchor, or the rules do nothing. Another program (a VPN client)
    /// may stop pf or replace its main ruleset at any time; `PFHeal` decides what may be put right.
    private func watchdog(now: Date, force: Bool = false) {
        guard force || now.timeIntervalSince(lastWatchdog) >= settings.watchdogInterval else { return }
        lastWatchdog = now
        heal(now: now, force: force)
        // Which process opened each VPN tunnel: a scan of every socket, so it runs off the watch loop.
        if now.timeIntervalSince(lastTunnelScan) >= 5 {
            lastTunnelScan = now
            background.async { [self] in
                let t = NetworkRoutes.tunnelOwners()
                tunnelLock.withLock { tunnels = t }
            }
        }
    }

    private func heal(now: Date, force: Bool) {
        let info = capture("/sbin/pfctl", ["-s", "info"])
        guard !info.isEmpty else { return }   // no pfctl
        pfEnabled = info.contains("Status: Enabled")
        var rules = capture("/sbin/pfctl", ["-s", "rules"])
        anchorHooked = PFStates.hooksAnchor(rules, anchor: settings.anchor)
        // Another program's anchors evaluated before Rat's are read too: a `pass … quick` in one ends pf's
        // evaluation before Rat's rules are reached. (Nothing to read on a Mac where Apple's anchors come first.)
        let anchorRules = Dictionary(PFHeal.anchorsBeforeHook(rules, anchor: settings.anchor).map { ($0, capture("/sbin/pfctl", ["-a", $0, "-s", "rules"])) },
                                     uniquingKeysWith: { a, _ in a })
        let shadowed = anchorHooked && PFHeal.shadowingRule(rules: rules, anchor: settings.anchor, anchorRules: anchorRules) != nil
        if pfEnabled, anchorHooked, !shadowed, !force {
            pfIssue = nil
            verifyAnchor(now: now)
            return
        }
        // Another program that keeps undoing the repair is not fought every 2 s: after five repairs in a minute,
        // once every 30 s.
        recentRepairs = recentRepairs.filter { now.timeIntervalSince($0) < 60 }
        if !force, recentRepairs.count >= 5, let last = recentRepairs.last, now.timeIntervalSince(last) < 30 {
            pfIssue = "Another program keeps turning pf off or replacing its rules (\(recentRepairs.count) repairs in the last minute); Rat repairs it every 30 s."
            return
        }
        let nat = capture("/sbin/pfctl", ["-s", "nat"])
        let config = (try? String(contentsOfFile: settings.systemConfig, encoding: .utf8)) ?? ""
        var done: String?
        switch PFHeal.plan(enabled: pfEnabled, rules: rules, nat: nat, config: config, anchor: settings.anchor, anchorRules: anchorRules, force: force) {
        case .none:
            pfIssue = nil
        case .enable:
            enablePF()
            done = "turned pf on again"
        case .reloadSystemConfig:
            _ = run("/sbin/pfctl", ["-f", settings.systemConfig], nil)
            enablePF()
            done = "loaded \(settings.systemConfig) and turned pf on"
        case .rehook(let ruleset):
            // Parsed first, so a ruleset pfctl rejects never replaces the main one halfway.
            if run("/sbin/pfctl", ["-n", "-N", "-R", "-f", "-"], ruleset) == 0, run("/sbin/pfctl", ["-N", "-R", "-f", "-"], ruleset) == 0 {
                done = shadowed ? "put the com.apple anchors first in pf's main ruleset" : "restored the com.apple anchors in pf's main ruleset"
            } else {
                pfIssue = "pf's main ruleset no longer evaluates the com.apple anchors, and restoring them failed."
            }
        case .blocked(let why):
            pfIssue = why
        }
        guard let done else { return }
        recentRepairs.append(now)
        record(done, now: now)
        // Our anchor is loaded again on this pass, whatever the reload kept.
        loaded = false
        pfEnabled = capture("/sbin/pfctl", ["-s", "info"]).contains("Status: Enabled")
        rules = capture("/sbin/pfctl", ["-s", "rules"])
        anchorHooked = PFStates.hooksAnchor(rules, anchor: settings.anchor)
        pfIssue = pfEnabled && anchorHooked ? nil : "Rat \(done), but pf still \(pfEnabled ? "does not evaluate its rules" : "is off")."
    }

    private func record(_ repair: String, now: Date) {
        repairs += 1
        lastRepair = repair
        lastRepairAt = now
    }

    /// Our anchor's rules can disappear while the ports to block stay the same (another program flushes the
    /// com.apple anchors, or loads /etc/pf.anchors/com.apple again), and `settle` loads only what changed. So pf's
    /// copy is read back and, when it no longer blocks what was loaded, everything is loaded again on this pass.
    private func verifyAnchor(now: Date) {
        guard loaded, !(loadedPorts.isEmpty && loadedLoopbackPorts.isEmpty) else { return }
        let text = capture("/sbin/pfctl", ["-a", settings.anchor, "-s", "rules"])
        guard !PFRules.holds(text, ports: loadedPorts, loopback: loadedLoopbackPorts) else { return }
        // Every port counts as new, so a state another ruleset kept for one in the meantime is killed as well.
        loadedPorts = []
        loadedLoopbackPorts = []
        loaded = false
        record("loaded Rat's rules again (pf had dropped them)", now: now)
    }

    static func modified(_ path: String) -> Date? {
        var st = stat()
        guard stat(path, &st) == 0 else { return nil }
        return Date(timeIntervalSince1970: Double(st.st_mtimespec.tv_sec) + Double(st.st_mtimespec.tv_nsec) / 1e9)
    }

    private func publishStatus(now: Date) {
        guard let file = settings.statusFile, now.timeIntervalSince(lastStatus) >= 1 else { return }
        lastStatus = now
        let status = EnforcerStatus(pid: getpid(), updated: now, pfEnabled: pfEnabled, anchorHooked: anchorHooked,
                                    deniedApps: portsByApp.mapValues { EnforcerStatus.App(processes: $0.processes, ports: $0.ports.count) },
                                    blockedPorts: loadedPorts.count,
                                    ruleDenied: portsByRuleApp.mapValues { EnforcerStatus.App(processes: $0.processes, ports: $0.ports.count) },
                                    denyRules: denyRuleCount, blockedLoopbackPorts: loadedLoopbackPorts.count,
                                    proxyCapture: settings.proxiedFile == nil ? nil : proxyWatch?.capturing ?? false,
                                    tunnels: tunnelLock.withLock { tunnels },
                                    pfIssue: pfIssue, repairs: repairs, lastRepair: lastRepair, lastRepairAt: lastRepairAt,
                                    executableSHA256: executableSHA256)
        let enc = JSONEncoder()
        enc.dateEncodingStrategy = .secondsSince1970
        guard let data = try? enc.encode(status) else { return }
        let tmp = file + ".tmp"
        if FileManager.default.createFile(atPath: tmp, contents: data, attributes: [.posixPermissions: 0o644]) {
            _ = rename(tmp, file)
        }
    }

    private var lastFileCheck = Date.distantPast

    /// The file is written by Rat as the user, so it is read as untrusted: at most `maxRulesFile` bytes, and one that
    /// does not parse counts as no rules (the deny list and Rat's ports still apply).
    static let maxRulesFile = 8 << 20

    private func loadRules(_ path: String) {
        var d: DaemonRules?
        if let h = FileHandle(forReadingAtPath: path) {
            defer { try? h.close() }
            if let data = try? h.read(upToCount: Self.maxRulesFile + 1), data.count <= Self.maxRulesFile { d = DaemonRules.decode(data) }
        }
        let j = d.flatMap { $0.hasProcessDenies ? SocketJudge($0) : nil }
        // Which processes are read depends only on what deny rules name; new names only judge sockets again.
        if j?.watchList != judge?.watchList { watched.removeAll(); watchedChanged = true; verdictCache.removeAll(); deniedPIDs.removeAll() }
        judge = j
        socketVerdicts.removeAll()
        denyRuleCount = d?.rules.filter { $0.enabled && $0.verdict == .deny && $0.processPath != nil }.count ?? 0
        if trace { FileHandle.standardError.write(Data("deny rules: \(denyRuleCount), watching \(j?.watchList.count ?? 0) programs\n".utf8)) }
    }

    /// Re-reads the deny list and port list when they changed. Checked every 50 ms with one `stat` each
    /// (FileManager's attribute lookup costs three system calls and showed up in profiles at a 3 ms pass rate).
    private func refreshFiles(now: Date) {
        guard now.timeIntervalSince(lastFileCheck) >= 0.05 else { return }
        lastFileCheck = now
        let stamp = Self.modified
        let d = stamp(settings.deniedFile)
        if d != deniedStamp {
            deniedStamp = d
            denied = DeniedApps(text: (try? String(contentsOfFile: settings.deniedFile, encoding: .utf8)) ?? "")
            // Every running process is classified again, so an app that was just denied is scanned on this pass.
            verdictCache.removeAll()
            deniedPIDs.removeAll()
        }
        if let pf = settings.portsFile {
            let f = stamp(pf)
            if f != portsStamp {
                portsStamp = f
                let text = (try? String(contentsOfFile: pf, encoding: .utf8)) ?? ""
                filePorts = PFRules.parsePorts(text)
                fileLoopbackPorts = PFRules.parseLoopbackPorts(text)
            }
        }
        if let rf = settings.rulesFile {
            let r = stamp(rf)
            if r != rulesStamp {
                rulesStamp = r
                loadRules(rf)
            }
        }
        if let file = settings.repairFile, let r = stamp(file), r != repairStamp {
            repairStamp = r
            watchdog(now: now, force: true)
        }
    }
}

/// Parsing of `pfctl -s states` / `-s rules` output.
public enum PFStates {
    /// (local address, remote address) of states whose local side uses one of `localPorts`.
    /// Lines look like `ALL tcp 192.168.1.5:54104 -> 141.95.207.211:443 ESTABLISHED:ESTABLISHED` (IPv6: `addr[port]`).
    public static func pairs(in text: String, localPorts: Set<Int>) -> [(String, String)] {
        var out: [(String, String)] = []
        var seen = Set<String>()
        for line in text.split(whereSeparator: \.isNewline) {
            let t = line.split(separator: " ", omittingEmptySubsequences: true).map(String.init)
            guard t.count >= 5, ["tcp", "udp"].contains(t[1]), t[3] == "->" || t[3] == "<-",
                  let local = endpoint(t[2]), let remote = endpoint(t[4]), localPorts.contains(local.port) else { continue }
            if seen.insert(local.address + " " + remote.address).inserted { out.append((local.address, remote.address)) }
        }
        return out
    }

    static func endpoint(_ s: String) -> (address: String, port: Int)? {
        if s.hasSuffix("]"), let open = s.lastIndex(of: "[") {
            guard let port = Int(s[s.index(after: open)..<s.index(before: s.endIndex)]) else { return nil }
            return (String(s[..<open]), port)
        }
        guard let colon = s.lastIndex(of: ":"), let port = Int(s[s.index(after: colon)...]) else { return nil }
        return (String(s[..<colon]), port)
    }

    /// Whether the main ruleset evaluates the anchor (macOS ships `anchor "com.apple/*"` in /etc/pf.conf).
    public static func hooksAnchor(_ mainRules: String, anchor: String) -> Bool {
        let parent = anchor.split(separator: "/").first.map(String.init) ?? anchor
        return mainRules.contains("anchor \"\(anchor)\"") || mainRules.contains("anchor \"\(parent)/*\"")
    }
}
