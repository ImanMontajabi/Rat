import Foundation
import os

private let logger = Logger(subsystem: "com.imanmontajabi.Rat", category: "enforcer")

/// Applies "deny" decisions with the macOS packet filter.
///
/// Rat has no Network Extension entitlement, so it cannot intercept connections per process.
/// Instead it collects the server addresses of denied apps and, when the user clicks Apply,
/// runs the bundled `rat-pf-helper.sh` once with administrator rights (the standard macOS
/// password prompt). The helper loads the addresses into a `pf` table and kills existing
/// connections to them. Nothing is installed permanently; pf rules last until reboot or
/// until the user clears them. A blocked address is blocked for every app on the Mac.
@MainActor
final class Enforcer: ObservableObject {
    @Published private(set) var applied: Set<String> = []
    @Published private(set) var busy = false
    @Published var lastError: String?

    private let listURL: URL

    init(supportDirectory: URL) {
        listURL = supportDirectory.appendingPathComponent("blocklist.txt")
    }

    /// Addresses wanted but not yet loaded into pf.
    func pending(for wanted: Set<String>) -> Set<String> { wanted.subtracting(applied) }

    /// Addresses loaded into pf that are no longer wanted.
    func stale(for wanted: Set<String>) -> Set<String> { applied.subtracting(wanted) }

    func needsApply(for wanted: Set<String>) -> Bool { wanted != applied }

    func apply(_ wanted: Set<String>) {
        guard !busy else { return }
        guard let helper = Bundle.main.url(forResource: "rat-pf-helper", withExtension: "sh")?.path else {
            lastError = "Helper script missing from the app bundle."
            return
        }
        busy = true
        lastError = nil
        do {
            try wanted.sorted().joined(separator: "\n").appending("\n").write(to: listURL, atomically: true, encoding: .utf8)
        } catch {
            busy = false
            lastError = error.localizedDescription
            return
        }
        let list = listURL.path
        Task.detached {
            let p = Process()
            p.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
            let command = "/bin/sh \(Self.shellQuote(helper)) \(Self.shellQuote(list))"
            p.arguments = ["-e", "do shell script \"\(Self.appleScriptEscape(command))\" with administrator privileges with prompt \"Rat needs permission to update the firewall.\""]
            let err = Pipe()
            p.standardError = err
            p.standardOutput = FileHandle.nullDevice
            try? p.run()
            p.waitUntilExit()
            let msg = String(decoding: err.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
            await MainActor.run {
                self.busy = false
                if p.terminationStatus == 0 {
                    self.applied = wanted
                    logger.notice("pf blocklist applied: \(wanted.count, privacy: .public) addresses")
                } else {
                    self.lastError = msg.contains("-128") ? "Cancelled." : msg.trimmingCharacters(in: .whitespacesAndNewlines)
                    logger.error("pf apply failed")
                }
            }
        }
    }

    nonisolated static func shellQuote(_ s: String) -> String { "'" + s.replacingOccurrences(of: "'", with: "'\\''") + "'" }

    nonisolated static func appleScriptEscape(_ s: String) -> String {
        s.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"")
    }
}
