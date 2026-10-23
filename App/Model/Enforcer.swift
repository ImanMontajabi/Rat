import Foundation
import os

private let logger = Logger(subsystem: "com.imanmontajabi.Rat", category: "enforcer")

/// Applies "deny" decisions with the macOS packet filter.
///
/// Rat has no Network Extension entitlement, so it cannot intercept connections per process. The root daemon
/// `rat-enforcerd` (a LaunchDaemon, installed once with the user's administrator password, opt-in) keeps the
/// `com.apple/rat` pf anchor in step with two files Rat writes:
///
/// * `denied-apps.txt`: apps that are denied outright. The daemon blocks the local ports of every socket of their
///   processes (helpers included), polling every few milliseconds.
/// * `denied-ports.txt`: local ports of sockets that a rule denied (for example one domain for all apps).
///
/// Only local ports are ever blocked. Remote addresses are shared by every app on the Mac (DNS resolvers, CDNs),
/// so Rat never puts them in the firewall. Without the helper nothing is enforced.
///
/// A second LaunchDaemon snapshots all processes' sockets so Rat can see system-wide traffic.
/// "Remove Helper" uninstalls both and clears the pf anchor.
@MainActor
final class Enforcer: ObservableObject {
    @Published private(set) var busy = false
    @Published private(set) var helperInstalled: Bool
    @Published private(set) var helperOutdated = false
    @Published var autoApply: Bool {
        didSet {
            UserDefaults.standard.set(autoApply, forKey: "autoApplyPF")
            if !autoApply { clearFiles() }
        }
    }
    @Published var lastError: String?

    static let applyLabel = "com.imanmontajabi.rat.pf"
    static let samplerLabel = "com.imanmontajabi.rat.sampler"
    static let helperPath = "/Library/PrivilegedHelperTools/com.imanmontajabi.rat.helper"
    static let enforcerPath = "/Library/PrivilegedHelperTools/com.imanmontajabi.rat.enforcer"
    static func plistPath(_ label: String) -> String { "/Library/LaunchDaemons/\(label).plist" }

    let snapshotURL: URL
    let appsURL: URL
    let portsURL: URL
    private var lastApps: Set<String>?
    private var lastPorts: Set<Int>?

    /// `helperInstalled` and `autoApply` can be forced so tests do not depend on (or touch) the machine's real state.
    init(supportDirectory: URL, helperInstalled: Bool? = nil, autoApply: Bool? = nil) {
        // Earlier versions wrote the server addresses of denied apps here and blocked them for every app.
        try? FileManager.default.removeItem(at: supportDirectory.appendingPathComponent("blocklist.txt"))
        snapshotURL = supportDirectory.appendingPathComponent("system-sockets.txt")
        appsURL = supportDirectory.appendingPathComponent("denied-apps.txt")
        portsURL = supportDirectory.appendingPathComponent("denied-ports.txt")
        self.helperInstalled = helperInstalled ?? FileManager.default.fileExists(atPath: Self.plistPath(Self.applyLabel))
        self.autoApply = autoApply ?? UserDefaults.standard.bool(forKey: "autoApplyPF")
        // Helpers before 1.0.4 also loaded a list of server addresses, which blocked them for every app.
        if helperInstalled == nil, self.helperInstalled {
            helperOutdated = !((try? String(contentsOfFile: Self.plistPath(Self.applyLabel), encoding: .utf8))?.contains("--ports") ?? false)
        }
    }

    /// Apps that are denied outright (bundle or executable paths). The daemon blocks every socket of their processes.
    func syncApps(_ paths: Set<String>) {
        guard helperInstalled, autoApply, paths != lastApps else { return }
        do {
            try paths.sorted().joined(separator: "\n").appending("\n").write(to: appsURL, atomically: true, encoding: .utf8)
            lastApps = paths
            logger.notice("denied apps written: \(paths.count, privacy: .public)")
        } catch {
            lastError = error.localizedDescription
        }
    }

    /// With auto-apply off nothing may stay blocked: the daemon is told there is nothing to block.
    private func clearFiles() {
        guard helperInstalled else { return }
        for url in [appsURL, portsURL] { try? "".write(to: url, atomically: true, encoding: .utf8) }
        lastApps = nil; lastPorts = nil
    }

    /// Local ports of sockets that rules deny. Rewritten on every pass while non-empty, because the daemon only
    /// trusts the file while it is fresh (a crashed Rat must not leave ports blocked).
    func syncPorts(_ ports: Set<Int>) {
        guard helperInstalled, autoApply else { return }
        guard !ports.isEmpty || lastPorts?.isEmpty == false else { lastPorts = ports; return }
        try? ports.sorted().map(String.init).joined(separator: "\n").appending("\n").write(to: portsURL, atomically: true, encoding: .utf8)
        lastPorts = ports
    }

    func installHelper() {
        guard let src = Bundle.main.url(forResource: "rat-pf-helper", withExtension: "sh")?.path else {
            lastError = "Helper script missing from the app bundle."
            return
        }
        guard let enforcer = Bundle.main.url(forAuxiliaryExecutable: "rat-enforcerd")?.path else {
            lastError = "Enforcer daemon missing from the app bundle."
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
        // The enforcer reads the user's files but only ever uses paths for matching and addresses for pf tables.
        let apply = plist(Self.applyLabel, [Self.enforcerPath, "--denied", appsURL.path, "--ports", portsURL.path],
                          extra: "<key>KeepAlive</key><true/><key>RunAtLoad</key><true/><key>ProcessType</key><string>Interactive</string>")
        let sampler = plist(Self.samplerLabel, [Self.helperPath, "snapshot", snapshotURL.path, owner],
                            extra: "<key>StartInterval</key><integer>5</integer><key>RunAtLoad</key><true/>")
        // The owner of the files the daemon writes into the user's support directory is the user, never root.
        let script = """
        set -e
        mkdir -p /Library/PrivilegedHelperTools
        install -m 755 -o root -g wheel \(Self.shellQuote(src)) \(Self.shellQuote(Self.helperPath))
        install -m 755 -o root -g wheel \(Self.shellQuote(enforcer)) \(Self.shellQuote(Self.enforcerPath))
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
            if ok { self.helperInstalled = true; self.helperOutdated = false; self.autoApply = true; self.lastApps = nil; self.lastPorts = nil }
        }
    }

    func removeHelper() {
        let script = """
        for l in \(Self.applyLabel) \(Self.samplerLabel); do /bin/launchctl bootout system/$l 2>/dev/null || true; done
        /sbin/pfctl -a com.apple/rat -F all >/dev/null 2>&1 || true
        rm -f \(Self.shellQuote(Self.plistPath(Self.applyLabel))) \(Self.shellQuote(Self.plistPath(Self.samplerLabel))) \(Self.shellQuote(Self.helperPath)) \(Self.shellQuote(Self.enforcerPath))
        """
        runPrivilegedScript(script) { ok in
            if ok { self.helperInstalled = false; self.helperOutdated = false; self.autoApply = false; self.lastApps = nil; self.lastPorts = nil }
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
