import XCTest
import RatMonitor
import RatEnforce
@testable import Rat

/// Live proxy unmasking, not demo data: a loopback proxy in this process (SOCKS5 and HTTP CONNECT, on 127.0.0.1
/// and ::1) answers real `curl` processes and holds their tunnels open without going anywhere, so the tests need
/// no network. Rat must show each flow as a proxied connection with the real destination, never as a socket to
/// 127.0.0.1.
///
/// The first test reads the clients' command lines (no root). The second checks the firewall helper's lo0
/// capture end to end and runs only where the helper is installed (`/var/run/com.imanmontajabi.rat.proxied.json`
/// is fresh); it reads that file and never writes anything outside a temporary folder.
@MainActor
final class LiveProxyTests: XCTestCase {
    private var proxy: HoldingProxy!
    private var clients: [Process] = []

    override func setUpWithError() throws {
        proxy = try HoldingProxy()
        AppSettings.shared.resolveProxiedHosts = false   // no DNS: the destinations are never contacted
    }

    override func tearDown() {
        for c in clients where c.isRunning { c.terminate() }
        clients = []
        proxy?.stop()
    }

    private func ledger(helperInstalled: Bool = false) throws -> (Ledger, URL) {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("rat-live-proxy-\(UUID())")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        addTeardownBlock { try? FileManager.default.removeItem(at: dir) }
        return (Ledger(directory: dir, helperInstalled: helperInstalled), dir)
    }

    /// Starts curl through the proxy. It waits for a TLS answer that never comes until the test ends.
    private func curl(_ args: [String]) throws -> Process {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/curl")
        p.arguments = ["-s", "-o", "/dev/null", "--max-time", "60"] + args
        p.standardOutput = FileHandle.nullDevice; p.standardError = FileHandle.nullDevice
        try p.run()
        clients.append(p)
        return p
    }

    /// The sockets of the clients and of this process (the proxy's listeners and its ends of the tunnels), once
    /// every client is connected. Other programs' connections are left out: the ledger would look up their names.
    private func liveConnections(of pids: [Int32], timeout: TimeInterval = 10) async throws -> [ObservedConnection] {
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            let conns = ConnectionSampler.sample()
            let ready = Set(conns.filter { pids.contains($0.pid) && $0.tcpState == "ESTABLISHED" && proxy.ports.contains($0.remotePort) }.map(\.pid))
            if ready.count == pids.count && proxy.handshakes >= pids.count { return conns.filter { pids.contains($0.pid) || $0.pid == getpid() } }
            try await Task.sleep(nanoseconds: 200_000_000)
        }
        XCTFail("curl did not connect to the loopback proxy (handshakes: \(proxy.handshakes))")
        return []
    }

    private var proxyName: String { (ConnectionSampler.path(of: getpid()) as NSString).lastPathComponent }

    private func proxied(_ l: Ledger, pid: Int32) -> [RemoteHost] { l.apps.flatMap(\.remotes).filter { $0.pid == pid && $0.via != nil } }

    func testCurlThroughLoopbackProxiesShowsTheRealDestination() async throws {
        let socks = try curl(["--socks5-hostname", "127.0.0.1:\(proxy.port4)", "https://example.com/"])
        let connect = try curl(["-x", "http://127.0.0.1:\(proxy.port4)", "https://1.1.1.1/"])
        let six = try curl(["-x", "socks5h://[::1]:\(proxy.port6)", "https://example.org:8443/"])
        let conns = try await liveConnections(of: [socks.processIdentifier, connect.processIdentifier, six.processIdentifier])
        let (l, _) = try ledger()
        await l.ingest(conns, [])

        let s = proxied(l, pid: socks.processIdentifier)
        XCTAssertEqual(s.map { "\($0.host):\($0.port)" }, ["example.com:443"])
        XCTAssertEqual(s.first?.via?.badge, "Proxy · \(proxyName)", "the tag names the program listening on the port")
        XCTAssertEqual(s.first?.via?.listener, "127.0.0.1:\(proxy.port4)")
        XCTAssertTrue(s.first?.isProxied ?? false)
        XCTAssertNil(s.first?.via?.server, "this proxy has no server of its own")

        let c = proxied(l, pid: connect.processIdentifier)
        XCTAssertEqual(c.map { "\($0.host):\($0.port)" }, ["1.1.1.1:443"])
        XCTAssertEqual(c.first?.address, "1.1.1.1")
        if l.geo.available { XCTAssertNotNil(c.first?.geo, "an unmasked address is placed on the map") }

        XCTAssertEqual(proxied(l, pid: six.processIdentifier).map { "\($0.host):\($0.port) \($0.via?.listener ?? "")" }, ["example.org:8443 [::1]:\(proxy.port6)"])

        let loopback = l.apps.flatMap(\.remotes).filter { [socks, connect, six].map(\.processIdentifier).contains($0.pid ?? 0) && $0.via == nil }
        XCTAssertEqual(loopback.map(\.host), [], "no client row is left pointing at the proxy's loopback port")
    }

    func testFirewallHelperUnmasksTheHandshakesItSees() async throws {
        let file = URL(fileURLWithPath: Enforcer.proxiedPath)
        let modified = (try? FileManager.default.attributesOfItem(atPath: file.path))?[.modificationDate] as? Date
        try XCTSkipUnless(modified.map { Date().timeIntervalSince($0) < 120 } ?? false && FileManager.default.isReadableFile(atPath: file.path),
                          "needs the firewall helper (Settings › Security) capturing lo0")

        // What the helper read from the handshakes on lo0 (the clients' command lines play no part here).
        let socks = try curl(["--socks5-hostname", "127.0.0.1:\(proxy.port4)", "https://example.com/"])
        let connect = try curl(["-x", "http://127.0.0.1:\(proxy.port4)", "https://198.51.100.7/"])
        let pids = [socks.processIdentifier, connect.processIdentifier]
        let conns = try await liveConnections(of: pids)

        var flows: [ProxiedFlow] = []
        let deadline = Date().addingTimeInterval(15)
        while Date() < deadline {
            flows = ((try? Data(contentsOf: file)).flatMap(ProxiedFlows.decode)?.flows ?? []).filter { pids.contains($0.clientPID) }
            if flows.count >= 2 { break }
            try await Task.sleep(nanoseconds: 300_000_000)
        }
        let seen = flows.map { "\($0.clientPID) \($0.kind.rawValue) \($0.host):\($0.port) → \($0.proxyPort)" }.sorted()
        XCTAssertEqual(seen, ["\(socks.processIdentifier) SOCKS5 example.com:443 → \(proxy.port4)",
                              "\(connect.processIdentifier) HTTP CONNECT 198.51.100.7:443 → \(proxy.port4)"].sorted())
        XCTAssertTrue(flows.allSatisfy { $0.proxyPID == getpid() }, "the helper names the proxy's process")

        // The same flows through the ledger, as Rat reads them from the helper.
        let (l, dir) = try ledger(helperInstalled: true)
        let enc = JSONEncoder(); enc.dateEncodingStrategy = .secondsSince1970
        try enc.encode(ProxiedFlows(updated: Date(), flows: flows)).write(to: dir.appendingPathComponent("proxied.json"))
        await l.ingest(conns, [])
        let s = proxied(l, pid: socks.processIdentifier)
        XCTAssertEqual(s.map { "\($0.host) \($0.via?.kind ?? "") \($0.via?.badge ?? "")" }, ["example.com SOCKS5 Proxy · \(proxyName)"])
        XCTAssertEqual(proxied(l, pid: connect.processIdentifier).map(\.address), ["198.51.100.7"])
    }
}

/// A loopback proxy that completes SOCKS5 and HTTP CONNECT handshakes and then holds the tunnel open, reading
/// and discarding what the client sends. It never connects anywhere.
final class HoldingProxy: @unchecked Sendable {
    let port4: Int, port6: Int
    var ports: Set<Int> { [port4, port6] }
    private let listeners: [Int32]
    private let lock = NSLock()
    private var clients: [Int32] = []
    private var count = 0
    var handshakes: Int { lock.withLock { count } }

    init() throws {
        let (l4, p4) = try Self.listen(ipv6: false), (l6, p6) = try Self.listen(ipv6: true)
        listeners = [l4, l6]; port4 = p4; port6 = p6
        for fd in listeners { Thread { [weak self] in self?.accept(fd) }.start() }
    }

    func stop() {
        lock.withLock {
            for fd in listeners + clients { shutdown(fd, SHUT_RDWR); close(fd) }
            clients = []
        }
    }

    private static func listen(ipv6: Bool) throws -> (Int32, Int) {
        let fd = socket(ipv6 ? AF_INET6 : AF_INET, SOCK_STREAM, 0)
        guard fd >= 0 else { throw POSIXError(.EIO) }
        var one: Int32 = 1
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, socklen_t(MemoryLayout<Int32>.size))
        var ok: Int32
        if ipv6 {
            var a = sockaddr_in6(); a.sin6_family = sa_family_t(AF_INET6); a.sin6_addr = in6addr_loopback
            ok = withUnsafePointer(to: &a) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in6>.size)) } }
        } else {
            var a = sockaddr_in(); a.sin_family = sa_family_t(AF_INET); a.sin_addr.s_addr = inet_addr("127.0.0.1")
            ok = withUnsafePointer(to: &a) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) } }
        }
        guard ok == 0, Darwin.listen(fd, 16) == 0 else { close(fd); throw POSIXError(.EADDRINUSE) }
        var ss = sockaddr_storage(), len = socklen_t(MemoryLayout<sockaddr_storage>.size)
        _ = withUnsafeMutablePointer(to: &ss) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(fd, $0, &len) } }
        let port = withUnsafePointer(to: &ss) { p -> UInt16 in
            ipv6 ? p.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) { $0.pointee.sin6_port } : p.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { $0.pointee.sin_port }
        }
        return (fd, Int(UInt16(bigEndian: port)))
    }

    private func accept(_ fd: Int32) {
        while true {
            let c = Darwin.accept(fd, nil, nil)
            guard c >= 0 else { return }
            lock.withLock { clients.append(c) }
            Thread { [weak self] in self?.serve(c) }.start()
        }
    }

    private func read(_ fd: Int32, _ n: Int) -> [UInt8]? {
        var out: [UInt8] = []
        var buf = [UInt8](repeating: 0, count: n)
        while out.count < n {
            let r = recv(fd, &buf, n - out.count, 0)
            guard r > 0 else { return nil }
            out += buf.prefix(r)
        }
        return out
    }

    private func send(_ fd: Int32, _ bytes: [UInt8]) { _ = bytes.withUnsafeBytes { Darwin.send(fd, $0.baseAddress, bytes.count, 0) } }

    private func serve(_ fd: Int32) {
        guard let first = read(fd, 1) else { return }
        if first[0] == 5 {
            // SOCKS5: methods, then CONNECT with an IPv4, name or IPv6 address.
            guard let n = read(fd, 1), read(fd, Int(n[0])) != nil else { return }
            send(fd, [5, 0])
            guard let head = read(fd, 4) else { return }
            let length: Int
            switch head[3] {
            case 1: length = 4
            case 3: guard let l = read(fd, 1) else { return }; length = Int(l[0])
            case 4: length = 16
            default: return
            }
            guard read(fd, length + 2) != nil else { return }
            send(fd, [5, 0, 0, 1, 0, 0, 0, 0, 0, 0])
        } else {
            // HTTP CONNECT: the request head up to the blank line.
            var head = first
            while !head.suffix(4).elementsEqual([13, 10, 13, 10]) {
                guard head.count < 8192, let b = read(fd, 1) else { return }
                head += b
            }
            send(fd, Array("HTTP/1.1 200 Connection established\r\n\r\n".utf8))
        }
        lock.withLock { count += 1 }
        var sink = [UInt8](repeating: 0, count: 4096)
        while recv(fd, &sink, sink.count, 0) > 0 {}
    }
}
