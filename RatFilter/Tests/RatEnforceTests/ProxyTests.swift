import XCTest
@testable import RatEnforce
import RatMonitor

/// 1.1.0: destinations of connections through a local proxy, read on lo0.
final class ProxyTests: XCTestCase {
    // MARK: handshakes

    func testHTTPConnect() {
        XCTAssertEqual(ProxyHandshake.parse(Array("CONNECT api.github.com:443 HTTP/1.1\r\nHost: api.github.com:443\r\n\r\n".utf8)),
                       ProxyRequest(kind: .httpConnect, host: "api.github.com", port: 443))
        XCTAssertEqual(ProxyHandshake.parse(Array("CONNECT [2606:4700::1111]:443 HTTP/1.1\r\n\r\n".utf8)),
                       ProxyRequest(kind: .httpConnect, host: "2606:4700::1111", port: 443))
        XCTAssertEqual(ProxyHandshake.parse(Array("CONNECT 140.82.121.6:22 HTTP/1.0\r\n".utf8))?.host, "140.82.121.6")
        XCTAssertNil(ProxyHandshake.parse(Array("CONNECT example.com HTTP/1.1\r\n".utf8)), "CONNECT needs a port")
        XCTAssertNil(ProxyHandshake.parse(Array("CONNECT exa mple.com:443 HTTP/1.1\r\n".utf8)))
        XCTAssertNil(ProxyHandshake.parse(Array("CONNECT example.com:99999 HTTP/1.1\r\n".utf8)))
        XCTAssertNil(ProxyHandshake.parse(Array("CONNECT ex\u{1}ample.com:443 HTTP/1.1\r\n".utf8)))
    }

    func testAbsoluteURIRequestsButNotLocalServerRequests() {
        XCTAssertEqual(ProxyHandshake.parse(Array("GET http://example.com/index.html HTTP/1.1\r\nHost: example.com\r\n\r\n".utf8)),
                       ProxyRequest(kind: .httpProxy, host: "example.com", port: 80))
        XCTAssertEqual(ProxyHandshake.parse(Array("POST http://user:pw@Example.COM:8080?q=1 HTTP/1.1\r\n".utf8)),
                       ProxyRequest(kind: .httpProxy, host: "example.com", port: 8080))
        // A request to a local web server is not a proxy request, whatever its Host header says.
        XCTAssertNil(ProxyHandshake.parse(Array("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n".utf8)))
        XCTAssertNil(ProxyHandshake.parse(Array("GET http://example.com/ HTTP/2\r\n".utf8)))
        XCTAssertNil(ProxyHandshake.parse(Array("BREW http://example.com/ HTTP/1.1\r\n".utf8)))
        // A request line cut off by the capture length still names its host once the authority is complete.
        let long = "GET http://cdn.example.org/" + String(repeating: "a", count: 2000)
        XCTAssertEqual(ProxyHandshake.parse(Array(long.utf8))?.host, "cdn.example.org")
        XCTAssertNil(ProxyHandshake.parse(Array("GET http://cdn.exam".utf8)), "an incomplete authority is not guessed")
    }

    func testSOCKS5() {
        let domain: [UInt8] = [5, 1, 0, 3, 17] + Array("www.wikipedia.org".utf8) + [0x01, 0xbb]
        XCTAssertEqual(ProxyHandshake.parse(domain), ProxyRequest(kind: .socks5, host: "www.wikipedia.org", port: 443))
        XCTAssertEqual(ProxyHandshake.parse([5, 1, 0, 1, 140, 82, 121, 6, 0x01, 0xbb]), ProxyRequest(kind: .socks5, host: "140.82.121.6", port: 443))
        let v6: [UInt8] = [5, 1, 0, 4, 0x26, 0x06, 0x47, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x11, 0x11, 0, 80]
        XCTAssertEqual(ProxyHandshake.parse(v6), ProxyRequest(kind: .socks5, host: "2606:4700::1111", port: 80))
        // The greeting and the request in one segment.
        XCTAssertEqual(ProxyHandshake.parse([5, 1, 0] + domain)?.host, "www.wikipedia.org")
        XCTAssertNil(ProxyHandshake.parse([5, 1, 0]), "the greeting alone names no destination")
        XCTAssertNil(ProxyHandshake.parse([5, 2, 0, 1, 1, 2, 3, 4, 0, 80]), "BIND is not a connection")
        XCTAssertNil(ProxyHandshake.parse([5, 1, 0, 1, 1, 2, 3, 4, 0, 80, 9]), "trailing bytes: not a SOCKS request")
        XCTAssertNil(ProxyHandshake.parse([5, 1, 0, 3, 3, 0x41, 0x20, 0x42, 0, 80]))
    }

    func testSOCKS4And4a() {
        XCTAssertEqual(ProxyHandshake.parse([4, 1, 0, 80, 93, 184, 216, 34, 0x75, 0x73, 0]), ProxyRequest(kind: .socks4, host: "93.184.216.34", port: 80))
        XCTAssertEqual(ProxyHandshake.parse([4, 1, 0x01, 0xbb, 0, 0, 0, 1, 0] + Array("example.com".utf8) + [0]),
                       ProxyRequest(kind: .socks4a, host: "example.com", port: 443))
        XCTAssertNil(ProxyHandshake.parse([4, 1, 0, 80, 93, 184, 216, 34]), "no user id terminator")
        XCTAssertNil(ProxyHandshake.parse([4, 2, 0, 80, 93, 184, 216, 34, 0]))
    }

    // MARK: frames

    static func frame(src: Int, dst: Int, payload: [UInt8], v6: Bool = false, ipOptions: Int = 0, tcpOptions: Int = 0, fragment: Int = 0) -> [UInt8] {
        var f: [UInt8] = v6 ? [30, 0, 0, 0] : [2, 0, 0, 0]
        let tcpLen = 20 + tcpOptions
        if v6 {
            f += [0x60, 0, 0, 0, UInt8((tcpLen + payload.count) >> 8), UInt8((tcpLen + payload.count) & 0xff), 6, 64]
            f += [UInt8](repeating: 0, count: 15) + [1] + [UInt8](repeating: 0, count: 15) + [1]
        } else {
            let ihl = 5 + ipOptions / 4
            let total = ihl * 4 + tcpLen + payload.count
            f += [UInt8(0x40 | ihl), 0, UInt8(total >> 8), UInt8(total & 0xff), 0, 0, UInt8(fragment >> 8), UInt8(fragment & 0xff), 64, 6, 0, 0, 127, 0, 0, 1, 127, 0, 0, 1]
            f += [UInt8](repeating: 1, count: ipOptions)
        }
        f += [UInt8(src >> 8), UInt8(src & 0xff), UInt8(dst >> 8), UInt8(dst & 0xff), 0, 0, 0, 1, 0, 0, 0, 0, UInt8((tcpLen / 4) << 4), 0x18, 0xff, 0xff, 0, 0, 0, 0]
        f += [UInt8](repeating: 1, count: tcpOptions)
        return f + payload
    }

    func testSegmentParsing() {
        let p = Array("CONNECT example.com:443 HTTP/1.1\r\n\r\n".utf8)
        XCTAssertEqual(LoopbackSegment.parse(Self.frame(src: 50123, dst: 1080, payload: p, tcpOptions: 12)),
                       LoopbackSegment(sourcePort: 50123, destinationPort: 1080, ipv6: false, payload: p))
        XCTAssertEqual(LoopbackSegment.parse(Self.frame(src: 50124, dst: 8080, payload: p, v6: true))?.ipv6, true)
        XCTAssertEqual(LoopbackSegment.parse(Self.frame(src: 1, dst: 2, payload: p, ipOptions: 8))?.payload, p)
        XCTAssertNil(LoopbackSegment.parse(Self.frame(src: 1, dst: 2, payload: p, fragment: 0x0010)))
        XCTAssertNil(LoopbackSegment.parse([2, 0, 0]))
    }

    // MARK: kernel filter

    /// The subset of classic BPF the filter uses, run here so the program is checked without root.
    static func runBPF(_ prog: [BPFInstruction], _ pkt: [UInt8]) -> UInt32 {
        var a: UInt32 = 0, x: UInt32 = 0, mem = [UInt32](repeating: 0, count: 16), pc = 0
        func load(_ off: Int, _ size: Int) -> UInt32? {
            guard off >= 0, off + size <= pkt.count else { return nil }
            return pkt[off..<(off + size)].reduce(0) { $0 << 8 | UInt32($1) }
        }
        while pc < prog.count {
            let i = prog[pc]; pc += 1
            switch i.code {
            case 0x20, 0x28, 0x30:   // ld abs w/h/b
                guard let v = load(Int(i.k), i.code == 0x20 ? 4 : i.code == 0x28 ? 2 : 1) else { return 0 }; a = v
            case 0x40, 0x50:         // ld ind w/b
                guard let v = load(Int(x) + Int(i.k), i.code == 0x40 ? 4 : 1) else { return 0 }; a = v
            case 0xb1:               // ldx 4*([k]&0xf)
                guard let v = load(Int(i.k), 1) else { return 0 }; x = (v & 0xf) * 4
            case 0x54: a &= i.k
            case 0x74: a >>= i.k
            case 0x0c: a &+= x
            case 0x07: x = a
            case 0x02: mem[Int(i.k)] = a
            case 0x60: a = mem[Int(i.k)]
            case 0x05: pc += Int(i.k)
            case 0x15: pc += a == i.k ? Int(i.jt) : Int(i.jf)
            case 0x45: pc += a & i.k != 0 ? Int(i.jt) : Int(i.jf)
            case 0x06: return i.k
            default: XCTFail("unexpected opcode \(i.code)"); return 0
            }
        }
        XCTFail("fell off the end"); return 0
    }

    func testKernelFilterPassesProxyRequestsOnly() {
        let prog = LoopbackFilter.program(snap: 600)
        let socks: [UInt8] = [5, 1, 0, 3, 11] + Array("example.com".utf8) + [1, 0xbb]
        for (payload, v6, opts) in [(Array("CONNECT a.b:443 HTTP/1.1\r\n".utf8), false, 0), (Array("GET http://a.b/ HTTP/1.1\r\n".utf8), true, 0),
                                    (socks, false, 12), (socks, true, 0), ([4, 1, 0, 80, 1, 2, 3, 4, 0], false, 8)] {
            XCTAssertEqual(Self.runBPF(prog, Self.frame(src: 50000, dst: 1080, payload: payload, v6: v6, tcpOptions: opts)), 600, "\(payload.prefix(8)) v6=\(v6)")
        }
        // TLS records, SOCKS replies, a bare SOCKS greeting, empty ACKs and later fragments stay in the kernel.
        for (payload, v6) in [([0x16, 3, 1, 0, 0xc8] as [UInt8], false), ([0x17, 3, 3, 0x40, 0], true), ([5, 0, 0, 1, 0, 0, 0, 0, 0, 0], false),
                              ([5, 1, 0], false), ([], false), (Array("HTTP/1.1 200 OK\r\n".utf8), false)] {
            XCTAssertEqual(Self.runBPF(prog, Self.frame(src: 1080, dst: 50000, payload: payload, v6: v6)), 0, "\(payload.prefix(5))")
        }
        XCTAssertEqual(Self.runBPF(prog, Self.frame(src: 1, dst: 2, payload: Array("CONNECT a:1 HTTP/1.1".utf8), fragment: 0x0020)), 0)
        // Every jump lands inside the program.
        for (n, i) in prog.enumerated() where i.code & 0x07 == 0x05 {
            XCTAssertLessThan(n + 1 + (i.code == 0x05 ? Int(i.k) : max(Int(i.jt), Int(i.jf))), prog.count)
        }
    }

    func testBPFBufferSplitting() {
        func record(_ payload: [UInt8]) -> [UInt8] {
            var r = [UInt8](repeating: 0, count: 8)
            r += withUnsafeBytes(of: UInt32(payload.count).littleEndian, Array.init) + withUnsafeBytes(of: UInt32(payload.count).littleEndian, Array.init)
            r += [18, 0] + payload
            while r.count % 4 != 0 { r.append(0) }
            return r
        }
        let buf = record([1, 2, 3]) + record([4, 5, 6, 7, 8]) + [9, 9]
        XCTAssertEqual(LoopbackCapture.frames(in: buf, count: buf.count), [[1, 2, 3], [4, 5, 6, 7, 8]])
    }

    // MARK: flow table

    func testWatchKeepsOnlyTheOwnersFlowsAndPublishesThemPrivately() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("rat-proxy-\(UUID())")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let file = dir.appendingPathComponent("proxied.json").path
        var aliveNow = true
        let w = ProxyWatch(settings: .init(file: file, ownerUID: 501), lookup: { wanted in
            var out: [String: LoopbackOwners] = [:]
            for x in wanted {
                let uid: uid_t = x.clientPort == 50002 ? 502 : 501   // 50002 belongs to another account
                out["\(x.clientPort)>\(x.proxyPort)"] = LoopbackOwners(client: .init(pid: 4242, path: "/usr/bin/curl", uid: uid),
                                                                       proxy: .init(pid: 99, path: "/usr/bin/ssh", uid: 501))
            }
            return out
        }, alive: { _, _, _ in aliveNow })
        let t0 = Date(timeIntervalSince1970: 1_800_000_000)
        let socks: [UInt8] = [5, 1, 0, 3, 17] + Array("www.wikipedia.org".utf8) + [1, 0xbb]
        w.handle(frames: [Self.frame(src: 50001, dst: 1080, payload: Array("CONNECT example.com:443 HTTP/1.1\r\n\r\n".utf8)),
                          Self.frame(src: 50002, dst: 1080, payload: Array("CONNECT secret.example:443 HTTP/1.1\r\n\r\n".utf8)),
                          Self.frame(src: 50003, dst: 1080, payload: socks, v6: true),
                          Self.frame(src: 50004, dst: 3000, payload: Array("GET /api HTTP/1.1\r\nHost: localhost\r\n\r\n".utf8))], now: t0)
        let published = try XCTUnwrap(ProxiedFlows.decode(Data(contentsOf: URL(fileURLWithPath: file))))
        XCTAssertEqual(published.flows.map { "\($0.kind.rawValue) \($0.host):\($0.port) \($0.clientPort)>\($0.proxyPort)" }.sorted(),
                       ["HTTP CONNECT example.com:443 50001>1080", "SOCKS5 www.wikipedia.org:443 50003>1080"])
        XCTAssertEqual(published.flows.first?.proxyPath, "/usr/bin/ssh")
        XCTAssertEqual(published.flows.first?.clientPID, 4242)
        let perms = try FileManager.default.attributesOfItem(atPath: file)[.posixPermissions] as? Int
        XCTAssertEqual(perms, 0o600, "only the owner may read where its apps connect")

        // Closed connections stay listed for a while (a one-second curl must still reach Rat), then disappear.
        aliveNow = false
        w.housekeeping(now: t0.addingTimeInterval(2))
        XCTAssertTrue(w.snapshot.allSatisfy { $0.closed != nil })
        XCTAssertEqual(w.snapshot.count, 2)
        w.housekeeping(now: t0.addingTimeInterval(40))
        XCTAssertTrue(w.snapshot.isEmpty)
        XCTAssertEqual(ProxiedFlows.decode(try Data(contentsOf: URL(fileURLWithPath: file)))?.flows.count, 0)
    }

    func testWriteDoesNotFollowALinkAtTheTemporaryPath() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("rat-proxy-\(UUID())")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let victim = dir.appendingPathComponent("victim.txt")
        try "keep".write(to: victim, atomically: true, encoding: .utf8)
        let file = dir.appendingPathComponent("proxied.json").path
        try FileManager.default.createSymbolicLink(atPath: file + ".tmp", withDestinationPath: victim.path)
        let w = ProxyWatch(settings: .init(file: file, ownerUID: getuid()), lookup: { wanted in
            Dictionary(uniqueKeysWithValues: wanted.map { ("\($0.clientPort)>\($0.proxyPort)", LoopbackOwners(client: .init(pid: 1, path: "/x", uid: getuid()), proxy: nil)) })
        }, alive: { _, _, _ in true })
        w.handle(frames: [Self.frame(src: 50001, dst: 1080, payload: Array("CONNECT example.com:443 HTTP/1.1\r\n\r\n".utf8))], now: Date())
        XCTAssertEqual(try String(contentsOf: victim, encoding: .utf8), "keep")
        XCTAssertEqual(ProxiedFlows.decode(try Data(contentsOf: URL(fileURLWithPath: file)))?.flows.count, 1)
    }

    /// The real libproc lookup: a loopback TCP connection inside this process is found from both ends.
    func testOwnerLookupFindsBothEndsOfALoopbackConnection() throws {
        let (listener, port) = tcpListener()
        defer { close(listener) }
        let client = socket(AF_INET, SOCK_STREAM, 0)
        defer { close(client) }
        var addr = sockaddr_in(); addr.sin_family = sa_family_t(AF_INET); addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        addr.sin_addr.s_addr = UInt32(0x7f000001).bigEndian; addr.sin_port = UInt16(port).bigEndian
        let rc = withUnsafePointer(to: &addr) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { connect(client, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) } }
        XCTAssertEqual(rc, 0)
        let accepted = accept(listener, nil, nil)
        defer { close(accepted) }
        var local = sockaddr_in(); var len = socklen_t(MemoryLayout<sockaddr_in>.size)
        withUnsafeMutablePointer(to: &local) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { _ = getsockname(client, $0, &len) } }
        let clientPort = Int(UInt16(bigEndian: local.sin_port))
        let owners = ProxyWatch.scanOwners([(clientPort, port)])["\(clientPort)>\(port)"]
        XCTAssertEqual(owners?.client?.pid, getpid())
        XCTAssertEqual(owners?.proxy?.pid, getpid())
        XCTAssertEqual(owners?.client?.uid, getuid())
        XCTAssertTrue(ProxyWatch.socketAlive(getpid(), clientPort, port))
        XCTAssertFalse(ProxyWatch.socketAlive(getpid(), clientPort, port + 1))
    }

    private func tcpListener() -> (Int32, Int) {
        let fd = socket(AF_INET, SOCK_STREAM, 0)
        var addr = sockaddr_in(); addr.sin_family = sa_family_t(AF_INET); addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        addr.sin_addr.s_addr = UInt32(0x7f000001).bigEndian
        withUnsafePointer(to: &addr) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { _ = Darwin.bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) } }
        listen(fd, 4)
        var bound = sockaddr_in(); var len = socklen_t(MemoryLayout<sockaddr_in>.size)
        withUnsafeMutablePointer(to: &bound) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { _ = getsockname(fd, $0, &len) } }
        return (fd, Int(UInt16(bigEndian: bound.sin_port)))
    }

    // MARK: loopback blocking

    func testLoopbackRulesBlockOnlyTheDeniedClientsPorts() {
        let r = PFRules.render(ports: [50000], loopbackPorts: [61001, 61000])
        XCTAssertTrue(r.contains("block return-rst out quick on lo0 proto tcp from any port { 61000 61001 } to any no state\n"))
        XCTAssertTrue(r.contains("block drop in quick on lo0 proto tcp from any to any port { 61000 61001 } no state\n"))
        XCTAssertTrue(r.contains("on ! lo0 proto tcp from any port { 50000 }"))
        for forbidden in ["table", "<", "pass"] { XCTAssertFalse(r.contains(forbidden), forbidden) }
        XCTAssertFalse(PFRules.render(ports: [50000]).contains("on lo0"), "no loopback rule without a loopback connection to cut")
        XCTAssertEqual(PFRules.parseLoopbackPorts("443\nlo0 61000\nlo0 x\nlo0 0\nlo0  61001\n"), [61000, 61001])
        XCTAssertEqual(PFRules.parsePorts("443\nlo0 61000\n"), [443])
    }

    func testDeniedAppsLoopbackConnectionsToOtherProgramsAreCut() {
        let sockets: [(entry: String, local: Int, remote: Int)] = [
            ("/Applications/Chrome.app", 61000, 1080),   // to an ssh -D proxy: cut
            ("/Applications/Chrome.app", 61001, 9222),   // between Chrome's own processes (Chrome listens on 9222): kept
            ("/Applications/Chrome.app", 9222, 61002),   // accepted by Chrome's own listener: kept
            ("/usr/bin/curl", 61003, 8443),              // to an ssh -L forward: cut
        ]
        XCTAssertEqual(EnforcerDaemon.loopbackPortsToBlock(sockets, listening: ["/Applications/Chrome.app": [9222]]), [61000, 61003])
    }

    /// The daemon's own pass: this test process is "denied" and connects to a loopback port. Its listener is its own,
    /// so nothing on lo0 is blocked; ports named by Rat as `lo0 <port>` are.
    func testDaemonLoopbackPass() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("rat-enf-\(UUID())")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let (listener, port) = tcpListener()
        defer { close(listener) }
        let client = socket(AF_INET, SOCK_STREAM, 0)
        defer { close(client) }
        var addr = sockaddr_in(); addr.sin_family = sa_family_t(AF_INET); addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        addr.sin_addr.s_addr = UInt32(0x7f000001).bigEndian; addr.sin_port = UInt16(port).bigEndian
        _ = withUnsafePointer(to: &addr) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { connect(client, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) } }
        try (ConnectionSampler.path(of: getpid()) + "\n").write(to: dir.appendingPathComponent("denied.txt"), atomically: true, encoding: .utf8)
        try "lo0 62000\n".write(to: dir.appendingPathComponent("ports.txt"), atomically: true, encoding: .utf8)
        var s = EnforcerDaemon.Settings(deniedFile: dir.appendingPathComponent("denied.txt").path, portsFile: dir.appendingPathComponent("ports.txt").path)
        s.anchor = "com.apple/rat-unittest"
        var loaded = ""
        let d = EnforcerDaemon(settings: s, run: { _, args, stdin in if args.contains("-f") { loaded = stdin ?? "" }; return 0 }, capture: { _, _ in "" })
        XCTAssertTrue(d.tick())
        XCTAssertEqual(d.loadedLoopbackPorts, [62000], "own loopback connections are kept; Rat's lo0 port is blocked")
        XCTAssertTrue(loaded.contains("on lo0 proto tcp from any port { 62000 }"), loaded)
    }

    func testStatusDecodesFromOlderDaemons() throws {
        let old = #"{"pid":1,"updated":1800000000,"pfEnabled":true,"anchorHooked":true,"deniedApps":{},"blockedPorts":0}"#
        let dec = JSONDecoder(); dec.dateDecodingStrategy = .secondsSince1970
        let st = try dec.decode(EnforcerStatus.self, from: Data(old.utf8))
        XCTAssertNil(st.proxyCapture)
        XCTAssertNil(st.blockedLoopbackPorts)
    }
}
