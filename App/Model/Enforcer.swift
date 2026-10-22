import Foundation
import os

private let logger = Logger(subsystem: "com.imanmontajabi.Rat", category: "enforcer")

/// Applies "deny" decisions with the macOS packet filter.
///
/// Rat has no Network Extension entitlement, so it cannot intercept connections per process.
/// Instead it collects the server addresses of denied connections and loads them into a `pf` table
/// through the bundled `rat-pf-helper.sh`, which runs as root. Two ways to run it:
///
/// * **Manual** (default): each click on "Apply blocking" runs the helper once behind the standard
///   macOS password prompt. Nothing stays installed.
/// * **Automatic** (opt-in, explicitly approved by the user): the helper is installed once as two root
///   LaunchDaemons. One re-applies the blocklist whenever Rat rewrites it, so Deny takes effect
///   immediately; the other snapshots all processes' sockets so Rat can see system-wide traffic.
///   "Remove Helper" uninstalls both and clears the pf anchor.
///
/// A blocked address is blocked for every app on the Mac.
@MainActor
final class Enforcer: ObservableObject {
    @Published private(set) var applied: Set<String> = []
    @Published private(set) var busy = false
    @Published private(set) var helperInstalled: Bool
    @Published var autoApply: Bool { didSet { UserDefaults.standard.set(autoApply, forKey: "autoApplyPF") } }
    @Published var lastError: String?

    static let applyLabel = "com.imanmontajabi.rat.pf"
    static let samplerLabel = "com.imanmontajabi.rat.sampler"
    static let helperPath = "/Library/PrivilegedHelperTools/com.imanmontajabi.rat.helper"
    static func plistPath(_ label: String) -> String { "/Library/LaunchDaemons/\(label).plist" }

    let listURL: URL
    let snapshotURL: URL
    private var lastWritten: Set<String>?

    init(supportDirectory: URL) {
        listURL = supportDirectory.appendingPathComponent("blocklist.txt")
        snapshotURL = supportDirectory.appendingPathComponent("system-sockets.txt")
        helperInstalled = FileManager.default.fileExists(atPath: Self.plistPath(Self.applyLabel))
        autoApply = UserDefaults.standard.bool(forKey: "autoApplyPF")
    }

    func needsApply(for wanted: Set<String>) -> Bool { wanted != applied }

    /// Called whenever the wanted blocklist may have changed. With the helper installed and auto-apply on,
    /// writing the file is the whole job: the daemon watches it.
    func sync(_ wanted: Set<String>) {
        guard helperInstalled, autoApply, wanted != lastWritten else { return }
        if writeList(wanted) { applied = wanted }
    }

    /// One-off apply behind an admin prompt (used when the helper is not installed).
    func applyOnce(_ wanted: Set<String>) {
        guard !busy else { return }
        guard let helper = Bundle.main.url(forResource: "rat-pf-helper", withExtension: "sh")?.path else {
            lastError = "Helper script missing from the app bundle."
            return
        }
        guard writeList(wanted) else { return }
        let command = "/bin/sh \(Self.shellQuote(helper)) apply \(Self.shellQuote(listURL.path))"
        runPrivileged(command) { ok in if ok { self.applied = wanted } }
    }

    func installHelper() {
        guard let src = Bundle.main.url(forResource: "rat-pf-helper", withExtension: "sh")?.path else {
            lastError = "Helper script missing from the app bundle."
            return
        }
        let owner = NSUserName()
        func plist(_ label: String, _ args: [String], extra: String) -> String {
            """
            <?xml version="1.0" encoding="UTF-8"?>
            <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
            <plist version="1.0"><dict>
            <key>Label</key><string>\(label)</string>
            <key>ProgramArguments</key><array>\(args.map { "<string>\(xml($0))</string>" }.joined())</array>
            \(extra)
            </dict></plist>
            """
        }
        let apply = plist(Self.applyLabel, [Self.helperPath, "apply", listURL.path],
                          extra: "<key>WatchPaths</key><array><string>\(xml(listURL.path))</string></array><key>RunAtLoad</key><true/>")
        let sampler = plist(Self.samplerLabel, [Self.helperPath, "snapshot", snapshotURL.path, owner],
                            extra: "<key>StartInterval</key><integer>5</integer><key>RunAtLoad</key><true/>")
        // The owner of the files the daemon writes into the user's support directory is the user, never root.
        let script = """
        set -e
        mkdir -p /Library/PrivilegedHelperTools
        install -m 755 -o root -g wheel \(Self.shellQuote(src)) \(Self.shellQuote(Self.helperPath))
        cat > \(Self.shellQuote(Self.plistPath(Self.applyLabel))) <<'PLIST'
        \(apply)
        PLIST
        cat > \(Self.shellQuote(Self.plistPath(Self.samplerLabel))) <<'PLIST'
        \(sampler)
        PLIST
        for f in \(Self.shellQuote(Self.plistPath(Self.applyLabel))) \(Self.shellQuote(Self.plistPath(Self.samplerLabel))); do
          chown root:wheel "$f"; chmod 644 "$f"
        done
        for l in \(Self.applyLabel) \(Self.samplerLabel); do /bin/launchctl bootout system/$l 2>/dev/null || true; done
        /bin/launchctl bootstrap system \(Self.shellQuote(Self.plistPath(Self.applyLabel)))
        /bin/launchctl bootstrap system \(Self.shellQuote(Self.plistPath(Self.samplerLabel)))
        """
        runPrivilegedScript(script) { ok in
            if ok { self.helperInstalled = true; self.autoApply = true; self.lastWritten = nil }
        }
    }

    func removeHelper() {
        let script = """
        for l in \(Self.applyLabel) \(Self.samplerLabel); do /bin/launchctl bootout system/$l 2>/dev/null || true; done
        /sbin/pfctl -a com.apple/rat -F all >/dev/null 2>&1 || true
        rm -f \(Self.shellQuote(Self.plistPath(Self.applyLabel))) \(Self.shellQuote(Self.plistPath(Self.samplerLabel))) \(Self.shellQuote(Self.helperPath))
        """
        runPrivilegedScript(script) { ok in
            if ok { self.helperInstalled = false; self.autoApply = false; self.applied = []; self.lastWritten = nil }
        }
    }

    /// Latest root snapshot of all processes' sockets, if the helper is installed and the file is fresh.
    func systemSnapshotText() -> String? {
        guard helperInstalled,
              let attrs = try? FileManager.default.attributesOfItem(atPath: snapshotURL.path),
              let modified = attrs[.modificationDate] as? Date, Date().timeIntervalSince(modified) < 30 else { return nil }
        return try? String(contentsOf: snapshotURL, encoding: .utf8)
    }

    // MARK: plumbing

    @discardableResult
    private func writeList(_ ips: Set<String>) -> Bool {
        do {
            try ips.sorted().joined(separator: "\n").appending("\n").write(to: listURL, atomically: true, encoding: .utf8)
            lastWritten = ips
            logger.notice("blocklist written: \(ips.count, privacy: .public) addresses")
            return true
        } catch {
            lastError = error.localizedDescription
            logger.error("could not write blocklist: \(error.localizedDescription, privacy: .public)")
            return false
        }
    }

    private func runPrivilegedScript(_ script: String, done: @escaping (Bool) -> Void) {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("rat-\(UUID().uuidString).sh")
        do { try script.write(to: url, atomically: true, encoding: .utf8) } catch { lastError = error.localizedDescription; return }
        runPrivileged("/bin/sh \(Self.shellQuote(url.path))") { ok in
            try? FileManager.default.removeItem(at: url)
            done(ok)
        }
    }

    private func runPrivileged(_ command: String, done: @escaping (Bool) -> Void) {
        guard !busy else { return }
        busy = true
        lastError = nil
        Task.detached {
            let p = Process()
            p.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
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
                    logger.notice("privileged step succeeded")
                    done(true)
                } else {
                    self.lastError = msg.contains("-128") ? "Cancelled." : msg.trimmingCharacters(in: .whitespacesAndNewlines)
                    logger.error("privileged step failed")
                    done(false)
                }
            }
        }
    }

    nonisolated private func xml(_ s: String) -> String {
        s.replacingOccurrences(of: "&", with: "&amp;").replacingOccurrences(of: "<", with: "&lt;").replacingOccurrences(of: ">", with: "&gt;")
    }

    nonisolated static func shellQuote(_ s: String) -> String { "'" + s.replacingOccurrences(of: "'", with: "'\\''") + "'" }

    nonisolated static func appleScriptEscape(_ s: String) -> String {
        s.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"")
    }
}
