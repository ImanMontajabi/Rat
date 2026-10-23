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

/// Root daemon. Polls every ~50 ms; for every process that belongs to a denied app it reads all sockets and loads
/// their local ports into the pf anchor, so connections to servers Rat has never seen (CDN rotation, IPv6 fallback,
/// QUIC migration) are cut as well. Only ports are ever blocked, never remote addresses.
public final class EnforcerDaemon {
    public struct Settings {
        public var deniedFile: String
        /// Local ports of sockets that rules deny (written by Rat each pass); optional.
        public var portsFile: String?
        /// Older versions kept a list of server addresses here. It is deleted: addresses are never blocked.
        public var legacyBlocklistFile: String?
        public var anchor = "com.apple/rat"
        /// How often the process list is checked while a denied app is running (new processes are caught within this).
        public var interval: TimeInterval = 0.003
        /// Cached socket descriptors are trusted this long before every socket is read again.
        public var refreshInterval: TimeInterval = 0.25
        /// How often the sockets of denied apps are re-read.
        public var scanInterval: TimeInterval = 0.005
        public var idleInterval: TimeInterval = 0.25
        /// A process that just appeared is re-read on every pass for this long: it opens its first sockets right away.
        public var youngWindow: TimeInterval = 0.6
        /// Ports stay blocked this long after their socket disappears, to cover packets still in flight.
        public var portHold: TimeInterval = 5
        public init(deniedFile: String, portsFile: String? = nil, legacyBlocklistFile: String? = nil) {
            self.deniedFile = deniedFile; self.portsFile = portsFile; self.legacyBlocklistFile = legacyBlocklistFile
        }
    }

    private let settings: Settings
    private let run: CommandRunner
    private var denied = DeniedApps(text: "")
    private var deniedStamp: Date?
    private var filePorts: [Int] = []
    private var portsStamp: Date?
    private var verdictCache: [pid_t: Bool] = [:]
    private var lastScan = Date.distantPast
    private var deniedPIDs = Set<pid_t>()
    private var fdCache: [pid_t: [Int32: ObservedConnection]] = [:]
    private var lastRefresh = Date.distantPast
    private var young: [pid_t: Date] = [:]
    private var firstSeen: [pid_t: Date] = [:]
    public private(set) var lastTickDuration: TimeInterval = 0
    private var portSeen: [Int: Date] = [:]
    private var loadedPorts: [Int] = []
    private var loaded = false
    private var token: String?
    public private(set) var reloads = 0
    private let trace = ProcessInfo.processInfo.environment["RAT_TRACE"] != nil
    private var traceTicks = 0, traceTime = 0.0

    public init(settings: Settings, run: @escaping CommandRunner = runCommand) {
        self.settings = settings
        self.run = run
    }

    public func start() {
        // Take a reference on pf so it is enabled while we run (and put back when we stop).
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/sbin/pfctl")
        p.arguments = ["-E"]
        let err = Pipe()
        p.standardError = err
        p.standardOutput = FileHandle.nullDevice
        if (try? p.run()) != nil {
            p.waitUntilExit()
            let text = String(decoding: err.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
            token = text.components(separatedBy: "Token : ").dropFirst().first?.split(whereSeparator: \.isNewline).first.map(String.init)
        }
        // Start clean: whatever an earlier version left in the anchor (address tables, old ports) is removed.
        _ = run("/sbin/pfctl", ["-a", settings.anchor, "-F", "all"], nil)
        if let legacy = settings.legacyBlocklistFile { try? FileManager.default.removeItem(atPath: legacy) }
        loadedPorts = []
        loaded = true
    }

    public func stop() {
        _ = run("/sbin/pfctl", ["-a", settings.anchor, "-F", "all"], nil)
        if let token { _ = run("/sbin/pfctl", ["-X", token], nil) }
    }

    public func loop() {
        while true {
            let busy = tick()
            if trace, busy { traceTicks += 1; traceTime += lastTickDuration; if traceTicks == 400 { FileHandle.standardError.write(Data("avg tick \(Int(traceTime / 400 * 1e6)) us, reloads \(reloads)\n".utf8)); traceTicks = 0; traceTime = 0 } }
            Thread.sleep(forTimeInterval: busy ? settings.interval : settings.idleInterval)
        }
    }

    /// One pass. Returns whether a denied app currently has processes (so the loop should run fast).
    ///
    /// The process list is cheap and read every pass; the sockets of denied processes are re-read every
    /// `scanInterval`, or at once when a new process of a denied app appears.
    @discardableResult
    public func tick(now: Date = Date()) -> Bool {
        let began = Date()
        defer { lastTickDuration = Date().timeIntervalSince(began) }
        refreshFiles()
        guard !denied.isEmpty else {
            verdictCache.removeAll(); deniedPIDs.removeAll()
            settle(now: now, live: [])
            return false
        }
        let pids = ConnectionSampler.allPIDs()
        var current = Set<pid_t>()
        var newlyDenied: [pid_t] = []
        for pid in pids {
            current.insert(pid)
            let known = verdictCache[pid]
            if known == nil { firstSeen[pid] = now }
            // A new process is first a fork of its parent (a shell) and only then the program: until it is a second
            // old, its path is read again every pass so the exec is noticed.
            guard known == nil || (known == false && now.timeIntervalSince(firstSeen[pid] ?? now) < 1) else { continue }
            let path = ConnectionSampler.path(of: pid)
            let verdict = !path.hasPrefix("pid ") && denied.matches(path: path, responsiblePath: { ProcessGrouping.responsiblePath(of: pid) })
            verdictCache[pid] = verdict
            if verdict {
                newlyDenied.append(pid)
                if trace { FileHandle.standardError.write(Data("new denied pid \(pid) \(Int(Date().timeIntervalSince1970 * 1000) % 100000)\n".utf8)) }
            }
        }
        verdictCache = verdictCache.filter { current.contains($0.key) }
        firstSeen = firstSeen.filter { current.contains($0.key) }
        deniedPIDs = Set(verdictCache.filter(\.value).keys)
        for pid in newlyDenied { young[pid] = now }
        young = young.filter { current.contains($0.key) && now.timeIntervalSince($0.value) < settings.youngWindow }

        guard !deniedPIDs.isEmpty else { settle(now: now, live: []); return false }
        let full = now.timeIntervalSince(lastScan) >= settings.scanInterval
        if full { lastScan = now }
        let scan = full ? deniedPIDs : Set(young.keys)
        guard !scan.isEmpty else { return true }

        // Reading a socket is the expensive call, so only descriptors not seen before are read, except every
        // `refreshInterval` when all are. Ports of a socket never change once it is bound.
        let refresh = now.timeIntervalSince(lastRefresh) >= settings.refreshInterval
        if refresh { lastRefresh = now; fdCache.removeAll() }
        fdCache = fdCache.filter { deniedPIDs.contains($0.key) }
        var ports = Set<Int>()
        for pid in scan {
            var known = fdCache[pid] ?? [:]
            let fds = ConnectionSampler.socketFDs(of: pid)
            let path = known.isEmpty ? ConnectionSampler.path(of: pid) : (known.values.first?.processPath ?? "")
            for fd in fds where known[fd] == nil {
                guard let c = ConnectionSampler.connection(pid: pid, fd: fd, processPath: path) else { continue }
                if c.localPort != 0 { known[fd] = c }   // not yet bound: look again next pass
                else { continue }
            }
            known = known.filter { fds.contains($0.key) }
            fdCache[pid] = known
            for c in known.values where c.tcpState != "LISTEN" { ports.insert(c.localPort) }
        }
        settle(now: now, live: ports)
        return true
    }

    /// Loads the ports if they changed.
    private func settle(now: Date, live ports: Set<Int>) {
        // Ports named by Rat (sockets a rule denies) count while the file is fresh: Rat rewrites it every pass,
        // so a crashed Rat cannot leave ports blocked for good.
        let fresh = portsStamp.map { now.timeIntervalSince($0) < 10 } ?? false
        for p in ports.union(fresh ? filePorts : []) { portSeen[p] = now }
        portSeen = portSeen.filter { now.timeIntervalSince($0.value) < settings.portHold }
        let held = portSeen.keys.sorted()
        if held != loadedPorts || !loaded { apply(ports: held) }
    }

    private func apply(ports: [Int]) {
        let rules = PFRules.render(ports: ports)
        let t0 = Date()
        defer { if trace { FileHandle.standardError.write(Data("apply \(ports.count) ports in \(Int(Date().timeIntervalSince(t0) * 1000)) ms\n".utf8)) } }
        if rules.isEmpty { _ = run("/sbin/pfctl", ["-a", settings.anchor, "-F", "all"], nil) }
        else { _ = run("/sbin/pfctl", ["-a", settings.anchor, "-f", "-"], rules) }
        loadedPorts = ports
        loaded = true
        reloads += 1
    }

    private func refreshFiles() {
        func stamp(_ path: String) -> Date? { (try? FileManager.default.attributesOfItem(atPath: path))?[.modificationDate] as? Date }
        let d = stamp(settings.deniedFile)
        if d != deniedStamp {
            deniedStamp = d
            denied = DeniedApps(text: (try? String(contentsOfFile: settings.deniedFile, encoding: .utf8)) ?? "")
            verdictCache.removeAll()
        }
        if let pf = settings.portsFile {
            let f = stamp(pf)
            if f != portsStamp {
                portsStamp = f
                filePorts = PFRules.parsePorts((try? String(contentsOfFile: pf, encoding: .utf8)) ?? "")
            }
        }
    }
}
