import Darwin
import Foundation
import RatMonitor

/// A connection a client made through a local proxy: the client's loopback socket and the destination it asked for.
public struct ProxiedFlow: Codable, Equatable, Sendable {
    public var kind: ProxyRequest.Kind
    public var host: String
    public var port: Int
    public var clientPID: Int32
    public var clientPath: String
    /// The client's loopback socket: its own port and the proxy's listening port.
    public var clientPort: Int
    public var proxyPort: Int
    public var ipv6: Bool
    /// The process at the other end of the loopback connection (`ssh -D`, a local proxy), when it could be read.
    public var proxyPID: Int32?
    public var proxyPath: String?
    public var seen: Date
    public var closed: Date?

    public init(kind: ProxyRequest.Kind, host: String, port: Int, clientPID: Int32, clientPath: String, clientPort: Int, proxyPort: Int,
                ipv6: Bool = false, proxyPID: Int32? = nil, proxyPath: String? = nil, seen: Date, closed: Date? = nil) {
        self.kind = kind; self.host = host; self.port = port; self.clientPID = clientPID; self.clientPath = clientPath
        self.clientPort = clientPort; self.proxyPort = proxyPort; self.ipv6 = ipv6; self.proxyPID = proxyPID; self.proxyPath = proxyPath
        self.seen = seen; self.closed = closed
    }
}

/// What the daemon publishes for Rat: readable only by the user Rat runs as.
public struct ProxiedFlows: Codable, Equatable, Sendable {
    public var updated: Date
    public var flows: [ProxiedFlow]
    public init(updated: Date, flows: [ProxiedFlow]) { self.updated = updated; self.flows = flows }

    public static func decode(_ data: Data) -> ProxiedFlows? {
        let dec = JSONDecoder()
        dec.dateDecodingStrategy = .secondsSince1970
        return try? dec.decode(ProxiedFlows.self, from: data)
    }
}

/// The two ends of a loopback TCP connection, as libproc reports them.
public struct LoopbackOwners {
    public struct Process { public var pid: Int32; public var path: String; public var uid: uid_t }
    public var client: Process?
    public var proxy: Process?
    public init(client: Process?, proxy: Process?) { self.client = client; self.proxy = proxy }
}

/// Unmasks connections that go through a local proxy (an `ssh -D` SOCKS tunnel, an HTTP proxy on 127.0.0.1).
/// Outside the Mac only the proxy's own connection is visible (ssh to its server), but on lo0 the client still
/// sends the destination in plain text before the proxy encrypts anything: `CONNECT host:443`, a SOCKS request,
/// or an absolute `GET http://…`. The daemon reads just those first bytes (the kernel filter passes nothing else)
/// and publishes the destination with the client's process. Only connections of `ownerUID`'s processes are kept,
/// and the file is readable by that user alone, so one account never learns where another account's apps go.
public final class ProxyWatch {
    public struct Settings {
        public var file: String
        public var ownerUID: uid_t
        /// A closed connection stays listed this long, so a request that lasted a second still reaches Rat.
        public var linger: TimeInterval = 30
        public var maxFlows = 512
        public init(file: String, ownerUID: uid_t) { self.file = file; self.ownerUID = ownerUID }
    }

    public typealias OwnerLookup = (_ wanted: [(clientPort: Int, proxyPort: Int)]) -> [String: LoopbackOwners]
    public typealias AliveCheck = (_ pid: Int32, _ clientPort: Int, _ proxyPort: Int) -> Bool

    private let settings: Settings
    private let lookup: OwnerLookup
    private let alive: AliveCheck
    private let lock = NSLock()
    private var flows: [String: ProxiedFlow] = [:]
    private var lastLiveness = Date.distantPast
    private var written: Data?
    private var capture: LoopbackCapture?
    public private(set) var capturing = false

    public init(settings: Settings, lookup: @escaping OwnerLookup = ProxyWatch.scanOwners, alive: @escaping AliveCheck = ProxyWatch.socketAlive) {
        self.settings = settings
        self.lookup = lookup
        self.alive = alive
    }

    public var openCount: Int { lock.withLock { flows.values.filter { $0.closed == nil }.count } }
    public var snapshot: [ProxiedFlow] { lock.withLock { flows.values.sorted { $0.seen < $1.seen } } }

    static func key(_ s: LoopbackSegment, _ r: ProxyRequest) -> String { "\(s.ipv6 ? 6 : 4)|\(s.sourcePort)|\(s.destinationPort)|\(r.host)|\(r.port)" }
    static func portsKey(_ c: Int, _ p: Int) -> String { "\(c)>\(p)" }

    /// Starts reading lo0 on a thread of its own. Returns false when no BPF device could be opened.
    @discardableResult
    public func start() -> Bool {
        guard let cap = LoopbackCapture() else { return false }
        capture = cap
        capturing = true
        Thread.detachNewThread { [self] in
            while true {
                autoreleasepool {
                    let frames = cap.read()
                    let now = Date()
                    if !frames.isEmpty { handle(frames: frames, now: now) }
                    housekeeping(now: now)
                }
            }
        }
        return true
    }

    /// Records the proxy requests among captured frames.
    public func handle(frames: [[UInt8]], now: Date) {
        var found: [(LoopbackSegment, ProxyRequest)] = []
        for f in frames {
            guard let seg = LoopbackSegment.parse(f), !seg.payload.isEmpty, let req = ProxyHandshake.parse(seg.payload) else { continue }
            found.append((seg, req))
        }
        guard !found.isEmpty else { return }
        let owners = lookup(found.map { ($0.0.sourcePort, $0.0.destinationPort) })
        lock.withLock {
            for (seg, req) in found {
                guard let o = owners[Self.portsKey(seg.sourcePort, seg.destinationPort)], let client = o.client,
                      client.uid == settings.ownerUID else { continue }
                flows[Self.key(seg, req)] = ProxiedFlow(kind: req.kind, host: req.host, port: req.port, clientPID: client.pid, clientPath: client.path,
                                                        clientPort: seg.sourcePort, proxyPort: seg.destinationPort, ipv6: seg.ipv6,
                                                        proxyPID: o.proxy?.pid, proxyPath: o.proxy?.path, seen: now)
            }
            trim()
        }
        write(now: now)
    }

    /// Marks connections whose socket is gone as closed, forgets old ones and publishes changes.
    public func housekeeping(now: Date) {
        guard now.timeIntervalSince(lastLiveness) >= 1 else { return }
        lastLiveness = now
        let open = lock.withLock { flows.filter { $0.value.closed == nil } }
        var gone: [String] = []
        for (k, f) in open where !alive(f.clientPID, f.clientPort, f.proxyPort) { gone.append(k) }
        lock.withLock {
            for k in gone { flows[k]?.closed = now }
            flows = flows.filter { $0.value.closed.map { now.timeIntervalSince($0) < settings.linger } ?? true }
        }
        write(now: now)
    }

    private func trim() {
        guard flows.count > settings.maxFlows else { return }
        for (k, _) in flows.sorted(by: { ($0.value.closed ?? .distantFuture, $0.value.seen) < ($1.value.closed ?? .distantFuture, $1.value.seen) })
            .prefix(flows.count - settings.maxFlows) { flows[k] = nil }
    }

    /// Writes the file when the flows changed. The file lives in /var/run (root-owned, so no link can redirect the
    /// write) and is handed to the owner with mode 0600.
    private func write(now: Date) {
        let list = snapshot
        let enc = JSONEncoder()
        enc.dateEncodingStrategy = .secondsSince1970
        enc.outputFormatting = [.sortedKeys]
        guard let body = try? enc.encode(list), body != written,
              let data = try? enc.encode(ProxiedFlows(updated: now, flows: list)) else { return }
        written = body
        let tmp = settings.file + ".tmp"
        unlink(tmp)
        let fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0o600)
        guard fd >= 0 else { return }
        if getuid() == 0 { _ = fchown(fd, settings.ownerUID, gid_t(20)) }
        _ = data.withUnsafeBytes { Darwin.write(fd, $0.baseAddress, $0.count) }
        close(fd)
        _ = rename(tmp, settings.file)
    }

    public func removeFile() {
        unlink(settings.file)
    }

    // MARK: process lookup (libproc)

    public static func isLoopback(_ address: String) -> Bool {
        address.hasPrefix("127.") || address == "::1" || address.hasPrefix("::ffff:127.")
    }

    /// Finds which processes hold the two ends of each loopback connection: one pass over every process's sockets.
    public static func scanOwners(_ wanted: [(clientPort: Int, proxyPort: Int)]) -> [String: LoopbackOwners] {
        var clients: [String: (Int, Int)] = [:], proxies: [String: String] = [:]
        for w in wanted {
            clients[portsKey(w.clientPort, w.proxyPort)] = w
            proxies[portsKey(w.proxyPort, w.clientPort)] = portsKey(w.clientPort, w.proxyPort)
        }
        var out: [String: LoopbackOwners] = [:]
        var remaining = clients.count * 2
        for pid in ConnectionSampler.allPIDs() where remaining > 0 {
            var path: String?
            for fd in ConnectionSampler.socketFDs(of: pid) {
                guard let c = ConnectionSampler.connection(pid: pid, fd: fd, processPath: ""), c.proto == .tcp, isLoopback(c.remoteAddress) else { continue }
                let k = portsKey(c.localPort, c.remotePort)
                if clients[k] != nil, out[k]?.client == nil {
                    path = path ?? ConnectionSampler.path(of: pid)
                    out[k, default: LoopbackOwners(client: nil, proxy: nil)].client = .init(pid: pid, path: path!, uid: uid(of: pid))
                    remaining -= 1
                } else if let ck = proxies[k], out[ck]?.proxy == nil {
                    path = path ?? ConnectionSampler.path(of: pid)
                    out[ck, default: LoopbackOwners(client: nil, proxy: nil)].proxy = .init(pid: pid, path: path!, uid: uid(of: pid))
                    remaining -= 1
                }
            }
        }
        return out
    }

    public static func socketAlive(_ pid: Int32, _ clientPort: Int, _ proxyPort: Int) -> Bool {
        ConnectionSampler.socketFDs(of: pid).contains { fd in
            guard let c = ConnectionSampler.connection(pid: pid, fd: fd, processPath: "") else { return false }
            return c.localPort == clientPort && c.remotePort == proxyPort && c.tcpState != "TIME_WAIT" && c.tcpState != "CLOSED"
        }
    }

    public static func uid(of pid: Int32) -> uid_t {
        var info = proc_bsdinfo()
        let n = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, Int32(MemoryLayout<proc_bsdinfo>.size))
        return n == Int32(MemoryLayout<proc_bsdinfo>.size) ? info.pbi_uid : uid_t.max
    }
}
