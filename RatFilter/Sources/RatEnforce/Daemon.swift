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
/// QUIC migration) are cut as well. States towards the servers they reached are killed at once.
public final class EnforcerDaemon {
    public struct Settings {
        public var deniedFile: String
        public var blocklistFile: String
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
        public init(deniedFile: String, blocklistFile: String) { self.deniedFile = deniedFile; self.blocklistFile = blocklistFile }
    }

    private let settings: Settings
    private let run: CommandRunner
    private var denied = DeniedApps(text: "")
    private var deniedStamp: Date?
    private var blocklist: [String] = []
    private var blocklistStamp: Date?
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
    private var loadedAddresses: [String] = []
    private var killed = Set<String>()
    private var pendingKills: [String] = []
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
        apply(ports: [], addresses: blocklist)
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
            if !portSeen.isEmpty || !loadedPorts.isEmpty || blocklist != loadedAddresses { settle(now: now, live: []) }
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
        let remotes = Set<String>()
        settle(now: now, live: ports, remotes: remotes)
        return true
    }

    /// Loads the ports/addresses if they changed and kills the states towards servers not yet handled.
    private func settle(now: Date, live ports: Set<Int>, remotes: Set<String> = []) {
        for p in ports { portSeen[p] = now }
        portSeen = portSeen.filter { now.timeIntervalSince($0.value) < settings.portHold }
        let heldPorts = portSeen.keys.sorted()
        if heldPorts != loadedPorts || blocklist != loadedAddresses {
            apply(ports: heldPorts, addresses: blocklist)
        }
        for a in remotes.union(blocklist) where killed.insert(a).inserted { pendingKills.append(a) }
        killStates()
    }

    private func apply(ports: [Int], addresses: [String]) {
        let rules = PFRules.render(ports: ports, addresses: addresses)
        let t0 = Date()
        defer { if trace { FileHandle.standardError.write(Data("apply \(ports.count) ports in \(Int(Date().timeIntervalSince(t0) * 1000)) ms\n".utf8)) } }
        _ = run("/sbin/pfctl", ["-a", settings.anchor, "-f", "-"], rules)
        loadedPorts = ports
        loadedAddresses = addresses
        reloads += 1
    }

    private let killQueue = DispatchQueue(label: "rat.enforcer.kill", qos: .utility)

    /// Existing states survive new block rules, so each server address is killed once. This runs off the watch
    /// loop: a slow pfctl must never delay the detection of the next process.
    private func killStates() {
        let batch = Array(pendingKills.prefix(50))
        pendingKills.removeFirst(batch.count)
        guard !batch.isEmpty else { return }
        let run = self.run
        killQueue.async {
            for a in batch { _ = run("/sbin/pfctl", ["-k", a.contains(":") ? "::/0" : "0.0.0.0/0", "-k", a], nil) }
        }
    }

    private func refreshFiles() {
        func stamp(_ path: String) -> Date? { (try? FileManager.default.attributesOfItem(atPath: path))?[.modificationDate] as? Date }
        let d = stamp(settings.deniedFile)
        if d != deniedStamp {
            deniedStamp = d
            denied = DeniedApps(text: (try? String(contentsOfFile: settings.deniedFile, encoding: .utf8)) ?? "")
            verdictCache.removeAll()
        }
        let b = stamp(settings.blocklistFile)
        if b != blocklistStamp {
            blocklistStamp = b
            blocklist = PFRules.parseBlocklist((try? String(contentsOfFile: settings.blocklistFile, encoding: .utf8)) ?? "")
        }
    }
}
