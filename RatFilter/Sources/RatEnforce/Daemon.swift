import Darwin
import Foundation
import RatMonitor

/// Runs a command; returns its exit status. Injectable so tests never touch the firewall.
public typealias CommandRunner = (_ executable: String, _ arguments: [String], _ stdin: String?) -> Int32

public func runCommand(_ executable: String, _ arguments: [String], _ stdin: String?) -> Int32 {
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
    /// Loopback connections of denied apps to other apps' ports (local proxies, SSH forwards) blocked on lo0.
    public var blockedLoopbackPorts: Int?
    /// Whether the daemon reads proxy requests on lo0 (nil from daemons before 1.1.0).
    public var proxyCapture: Bool?

    public init(pid: Int32, updated: Date, pfEnabled: Bool, anchorHooked: Bool, deniedApps: [String: App], blockedPorts: Int,
                blockedLoopbackPorts: Int? = nil, proxyCapture: Bool? = nil) {
        self.pid = pid; self.updated = updated; self.pfEnabled = pfEnabled; self.anchorHooked = anchorHooked
        self.deniedApps = deniedApps; self.blockedPorts = blockedPorts
        self.blockedLoopbackPorts = blockedLoopbackPorts; self.proxyCapture = proxyCapture
    }
}

/// Root daemon. For every process that belongs to a denied app it reads all sockets on every pass (every 3 ms while
/// such a process runs) and loads their local ports into the pf anchor, so connections to servers Rat has never
/// seen (CDN rotation, IPv6 fallback, QUIC migration) are cut as well. Only ports are ever blocked, never remote
/// addresses. Loopback connections of denied processes to another app's port (a local proxy, an `ssh -L` forward)
/// are blocked on lo0, so a denied app cannot leave the Mac through a tunnel either.
public final class EnforcerDaemon {
    public struct Settings {
        public var deniedFile: String
        /// Local ports of sockets that rules deny (written by Rat each pass); optional.
        public var portsFile: String?
        /// Older versions kept a list of server addresses here. It is deleted: addresses are never blocked.
        public var legacyBlocklistFile: String?
        /// Where the daemon publishes `EnforcerStatus` as JSON; optional.
        public var statusFile: String?
        /// Where proxied connections of `ownerUID`'s processes are published (see `ProxyWatch`); optional.
        public var proxiedFile: String?
        public var ownerUID: uid_t?
        public var anchor = "com.apple/rat"
        /// Pass interval while a denied app has processes. Every pass reads the process list and every socket of
        /// every denied process (reading Chrome's ~30 processes takes about 0.05 ms).
        public var interval: TimeInterval = 0.003
        public var idleInterval: TimeInterval = 0.25
        /// Ports stay blocked this long after their socket disappears, to cover packets still in flight.
        public var portHold: TimeInterval = 5
        /// How often pf is checked to still be enabled (another tool may disable it).
        public var watchdogInterval: TimeInterval = 5
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
    /// pid -> the denied entry it belongs to ("" = not denied).
    private var verdictCache: [pid_t: String] = [:]
    private var firstSeen: [pid_t: Date] = [:]
    private var lastCleanup = Date.distantPast
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
    public private(set) var reloads = 0
    private let trace = !(ProcessInfo.processInfo.environment["RAT_TRACE"] ?? "").isEmpty
    private var traceTicks = 0, traceTime = 0.0

    public init(settings: Settings, run: @escaping CommandRunner = runCommand, capture: @escaping CommandCapture = captureCommand) {
        self.settings = settings
        self.run = run
        self.capture = capture
    }

    public func start() {
        enablePF()
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
        while true {
            let busy = tick()
            if trace, busy { traceTicks += 1; traceTime += lastTickDuration; if traceTicks == 400 { FileHandle.standardError.write(Data("avg tick \(Int(traceTime / 400 * 1e6)) us, reloads \(reloads)\n".utf8)); traceTicks = 0; traceTime = 0 } }
            Thread.sleep(forTimeInterval: busy ? settings.interval : settings.idleInterval)
        }
    }

    /// One pass. Returns whether a denied app currently has processes (so the loop should run fast).
    @discardableResult
    public func tick(now: Date = Date()) -> Bool {
        let began = Date()
        defer { lastTickDuration = Date().timeIntervalSince(began) }
        refreshFiles(now: now)
        watchdog(now: now)
        defer { publishStatus(now: now) }
        guard !denied.isEmpty else {
            verdictCache.removeAll(); deniedPIDs.removeAll(); portsByApp.removeAll()
            settle(now: now, live: [], loopback: [])
            return false
        }
        let pids = ConnectionSampler.allPIDs()
        for pid in pids {
            let known = verdictCache[pid]
            if known == nil { firstSeen[pid] = now }
            // A new process is first a fork of its parent (a shell) and only then the program: until it is a second
            // old, its path is read again every pass so the exec is noticed.
            guard known == nil || (known == "" && now.timeIntervalSince(firstSeen[pid] ?? now) < 1) else { continue }
            let path = ConnectionSampler.path(of: pid)
            let entry = path.hasPrefix("pid ") ? nil : denied.entry(for: path, responsiblePath: { ProcessGrouping.responsiblePath(of: pid) })
            verdictCache[pid] = entry ?? ""
            if entry != nil {
                deniedPIDs.insert(pid)
                if trace { FileHandle.standardError.write(Data("denied pid \(pid) (\(entry!))\n".utf8)) }
            }
        }
        // Forgetting processes that exited is the costly part (hundreds of entries), so it runs a few times a second;
        // reading the sockets of a process that just exited returns nothing in the meantime.
        if now.timeIntervalSince(lastCleanup) >= 0.25 {
            lastCleanup = now
            let current = Set(pids)
            verdictCache = verdictCache.filter { current.contains($0.key) }
            firstSeen = firstSeen.filter { current.contains($0.key) }
            deniedPIDs = deniedPIDs.filter { current.contains($0) }
        }
        guard !deniedPIDs.isEmpty else { portsByApp.removeAll(); settle(now: now, live: [], loopback: []); return false }

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
        settle(now: now, live: ports, loopback: Self.loopbackPortsToBlock(loopbackSockets, listening: listening))
        return true
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

    /// pf must stay enabled and our anchor must be evaluated, or the rules do nothing.
    private func watchdog(now: Date) {
        guard now.timeIntervalSince(lastWatchdog) >= settings.watchdogInterval else { return }
        lastWatchdog = now
        let info = capture("/sbin/pfctl", ["-s", "info"])
        pfEnabled = info.contains("Status: Enabled")
        if !pfEnabled, !info.isEmpty {
            enablePF()
            pfEnabled = capture("/sbin/pfctl", ["-s", "info"]).contains("Status: Enabled")
        }
        let main = capture("/sbin/pfctl", ["-s", "rules"])
        anchorHooked = PFStates.hooksAnchor(main, anchor: settings.anchor)
    }

    private func publishStatus(now: Date) {
        guard let file = settings.statusFile, now.timeIntervalSince(lastStatus) >= 1 else { return }
        lastStatus = now
        let status = EnforcerStatus(pid: getpid(), updated: now, pfEnabled: pfEnabled, anchorHooked: anchorHooked,
                                    deniedApps: portsByApp.mapValues { EnforcerStatus.App(processes: $0.processes, ports: $0.ports.count) },
                                    blockedPorts: loadedPorts.count, blockedLoopbackPorts: loadedLoopbackPorts.count,
                                    proxyCapture: settings.proxiedFile == nil ? nil : proxyWatch?.capturing ?? false)
        let enc = JSONEncoder()
        enc.dateEncodingStrategy = .secondsSince1970
        guard let data = try? enc.encode(status) else { return }
        let tmp = file + ".tmp"
        if FileManager.default.createFile(atPath: tmp, contents: data, attributes: [.posixPermissions: 0o644]) {
            _ = rename(tmp, file)
        }
    }

    private var lastFileCheck = Date.distantPast

    /// Re-reads the deny list and port list when they changed. Checked every 50 ms with one `stat` each
    /// (FileManager's attribute lookup costs three system calls and showed up in profiles at a 3 ms pass rate).
    private func refreshFiles(now: Date) {
        guard now.timeIntervalSince(lastFileCheck) >= 0.05 else { return }
        lastFileCheck = now
        func stamp(_ path: String) -> Date? {
            var st = stat()
            guard stat(path, &st) == 0 else { return nil }
            return Date(timeIntervalSince1970: Double(st.st_mtimespec.tv_sec) + Double(st.st_mtimespec.tv_nsec) / 1e9)
        }
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
