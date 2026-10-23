import XCTest
@testable import RatMonitor

final class ProcessArgumentsTests: XCTestCase {
    func testCurlThroughALocalProxy() {
        let a = ProcessArguments.from(arguments: ["curl", "-s", "--proxy", "http://127.0.0.1:8080", "-H", "Authorization: Bearer x", "https://api.github.com/user?token=secret"],
                                      environment: ["HOME=/Users/me", "AWS_SECRET=abc"])
        XCTAssertEqual(a.targets, [.init(host: "api.github.com", port: 443)])
        XCTAssertEqual(a.proxies, [.init(host: "127.0.0.1", port: 8080)])
        XCTAssertTrue(a.usesLocalProxy(port: 8080))
        XCTAssertFalse(a.usesLocalProxy(port: 1080))
    }

    func testEnvironmentProxiesAndSocks() {
        let a = ProcessArguments.from(arguments: ["git-remote-https", "origin", "https://user@github.com:8443/me/repo.git"],
                                      environment: ["ALL_PROXY=socks5h://localhost:1080", "https_proxy=http://[::1]:3128/", "NO_PROXY=x"])
        XCTAssertEqual(a.targets, [.init(host: "github.com", port: 8443)])
        XCTAssertEqual(Set(a.proxies), [.init(host: "localhost", port: 1080), .init(host: "::1", port: 3128)])
        XCTAssertTrue(a.usesLocalProxy(port: 1080))
        XCTAssertEqual(ProcessArguments.from(arguments: ["curl", "--socks5-hostname", "127.0.0.1:9050", "http://example.com"], environment: []).proxies,
                       [.init(host: "127.0.0.1", port: 9050)])
        // curl's -e is the referer, not a target.
        XCTAssertEqual(ProcessArguments.from(arguments: ["curl", "-e", "https://ref.example", "https://a.example"], environment: []).targets,
                       [.init(host: "a.example", port: 443)])
    }

    func testProcargsLayout() {
        var b: [UInt8] = [3, 0, 0, 0] + Array("/usr/bin/curl".utf8) + [0, 0, 0, 0]
        for s in ["curl", "-x", "127.0.0.1:1080", "LANG=en_US.UTF-8", "https_proxy=127.0.0.1:3128"] { b += Array(s.utf8) + [0] }
        let a = ProcessArguments.parse(b)
        XCTAssertEqual(a?.targets, [])
        XCTAssertEqual(a?.proxies, [.init(host: "127.0.0.1", port: 1080), .init(host: "127.0.0.1", port: 3128)])
        XCTAssertNotNil(ProcessArguments.read(pid: getpid()), "a process can read its own arguments")
    }
}
