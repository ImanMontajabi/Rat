import XCTest
@testable import RatEnforce

final class CommandRunnerTests: XCTestCase {
    private func openDescriptors() -> Int { (0..<4096).filter { fcntl(Int32($0), F_GETFD) != -1 }.count }

    /// The daemon runs pfctl from a detached thread whose autorelease pool is never drained. Each run used to keep
    /// its pipe open, so after a few hundred the daemon could not start pfctl any more and stopped enforcing.
    func testCommandsDoNotLeakDescriptorsOnADetachedThread() {
        let done = expectation(description: "runs")
        var before = 0, after = 0, outputs: [String] = [], statuses: [Int32] = []
        Thread.detachNewThread { [self] in
            before = openDescriptors()
            for _ in 0..<100 {
                outputs.append(captureCommand("/bin/echo", ["rat"]))
                statuses.append(runCommand("/bin/cat", [], "rat"))
                statuses.append(runCommand("/usr/bin/true", [], nil))
            }
            after = openDescriptors()
            done.fulfill()
        }
        wait(for: [done], timeout: 60)
        XCTAssertEqual(Set(outputs), ["rat\n"])
        XCTAssertEqual(Set(statuses), [0])
        XCTAssertLessThan(after - before, 5, "descriptors left open by 300 commands")
    }
}
