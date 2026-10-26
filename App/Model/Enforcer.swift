import Foundation
import os
import RatEnforce

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
    /// What the daemon last reported (nil when it is not running or has not written for a while).
    @Published private(set) var status: EnforcerStatus?
    @Published var lastError: String?

    static let applyLabel = "com.imanmontajabi.rat.pf"
    static let samplerLabel = "com.imanmontajabi.rat.sampler"
    static let helperPath = "/Library/PrivilegedHelperTools/com.imanmontajabi.rat.helper"
    static let enforcerPath = "/Library/PrivilegedHelperTools/com.imanmontajabi.rat.enforcer"
    static let statusPath = "/var/run/com.imanmontajabi.rat.enforcer.json"
    /// Destinations of connections through local proxies, published by the daemon for this user only (mode 0600).
    static let proxiedPath = "/var/run/com.imanmontajabi.rat.proxied.json"
    static func plistPath(_ label: String) -> String { "/Library/LaunchDaemons/\(label).plist" }

    let snapshotURL: URL
    let appsURL: URL
    let portsURL: URL
    private let statusURL: URL
    private let proxiedURL: URL
    private var proxiedStamp: Date?
    private var proxied: [ProxiedFlow] = []

    /// `helperInstalled` and the daemon's files can be forced so tests do not depend on (or touch) the machine's real state.
    init(supportDirectory: URL, helperInstalled: Bool? = nil, statusPath: String? = nil, proxiedPath: String? = nil) {
        // Earlier versions wrote the server addresses of denied apps here and blocked them for every app.
        try? FileManager.default.removeItem(at: supportDirectory.appendingPathComponent("blocklist.txt"))
        snapshotURL = supportDirectory.appendingPathComponent("system-sockets.txt")
        appsURL = supportDirectory.appendingPathComponent("denied-apps.txt")
        portsURL = supportDirectory.appendingPathComponent("denied-ports.txt")
        self.helperInstalled = helperInstalled ?? FileManager.default.fileExists(atPath: Self.plistPath(Self.applyLabel))
        statusURL = URL(fileURLWithPath: statusPath ?? Self.statusPath)
        proxiedURL = URL(fileURLWithPath: proxiedPath ?? Self.proxiedPath)
        // 1.0.4 and earlier had an "auto-apply" switch; a test could turn it off in the real preferences and Deny then
        // silently did nothing. With the helper installed, Deny is now always enforced.
        if !Preferences.isTesting && !Preferences.isDemo { UserDefaults.standard.removeObject(forKey: "autoApplyPF") }
        // Helpers before 1.1.0 do not read proxy requests on lo0 (before 1.0.5 they also published no status, and
        // before 1.0.4 they blocked server addresses for every app).
        if helperInstalled == nil, self.helperInstalled {
            helperOutdated = !((try? String(contentsOfFile: Self.plistPath(Self.applyLabel), encoding: .utf8))?.contains("--proxied") ?? false)
        }
    }

    /// Reads the daemon's status file. A status older than 10 s means the daemon is not running.
    func refreshStatus(now: Date = Date()) {
        let dec = JSONDecoder()
        dec.dateDecodingStrategy = .secondsSince1970
        let s = (try? Data(contentsOf: statusURL)).flatMap { try? dec.decode(EnforcerStatus.self, from: $0) }
        let fresh = s.flatMap { now.timeIntervalSince($0.updated) < 10 ? $0 : nil }
        if fresh != status { status = fresh }
    }

    /// Connections through local proxies the daemon saw on lo0 (re-read when the file changes).
    func proxiedFlows() -> [ProxiedFlow] {
        guard helperInstalled else { return [] }
        let modified = (try? FileManager.default.attributesOfItem(atPath: proxiedURL.path))?[.modificationDate] as? Date
        guard modified != proxiedStamp else { return proxied }
        proxiedStamp = modified
        proxied = (try? Data(contentsOf: proxiedURL)).flatMap(ProxiedFlows.decode)?.flows ?? []
        return proxied
    }

    /// Writes `text` unless the file already holds exactly that. Comparing with the file (not a cached copy) means a
    /// file that was deleted or changed behind Rat's back is put right on the next pass.
    @discardableResult
    private func write(_ text: String, to url: URL) -> Bool {
        if (try? String(contentsOf: url, encoding: .utf8)) == text { return false }
        do {
            try text.write(to: url, atomically: true, encoding: .utf8)
            return true
        } catch {
            lastError = error.localizedDescription
            return false
        }
    }

    /// Apps that are denied outright (bundle or executable paths). The daemon blocks every socket of their processes.
    func syncApps(_ paths: Set<String>) {
        guard helperInstalled else { return }
        if write(paths.sorted().map { $0 + "\n" }.joined(), to: appsURL) {
            logger.notice("denied apps written: \(paths.count, privacy: .public)")
        }
    }

    /// Local ports of sockets that rules deny, and (`lo0 <port>`) of loopback connections to a local proxy whose
    /// destination a rule denies. Rewritten on every pass while non-empty, because the daemon only trusts the file
    /// while it is fresh (a crashed Rat must not leave ports blocked).
    func syncPorts(_ ports: Set<Int>, loopback: Set<Int> = []) {
        guard helperInstalled else { return }
        let text = ports.sorted().map { "\($0)\n" }.joined() + loopback.sorted().map { "lo0 \($0)\n" }.joined()
        if ports.isEmpty && loopback.isEmpty { write(text, to: portsURL) }
        else { try? text.write(to: portsURL, atomically: true, encoding: .utf8) }
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
        // The enforcer reads the user's files only for matching. It publishes proxied destinations of this user's
        // processes (and nobody else's) in a file only this user can read.
        let apply = plist(Self.applyLabel, [Self.enforcerPath, "--denied", appsURL.path, "--ports", portsURL.path, "--status", Self.statusPath,
                                            "--proxied", Self.proxiedPath, "--owner-uid", String(getuid())],
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
        # bootout returns before launchd has unloaded the job; bootstrapping too early fails with an I/O error.
        for l in \(Self.applyLabel) \(Self.samplerLabel); do
          /bin/launchctl bootout system/$l 2>/dev/null || true
          i=0; while /bin/launchctl print system/$l >/dev/null 2>&1 && [ $i -lt 50 ]; do sleep 0.1; i=$((i + 1)); done
        done
        for p in \(Self.shellQuote(Self.plistPath(Self.applyLabel))) \(Self.shellQuote(Self.plistPath(Self.samplerLabel))); do
          n=0; until /bin/launchctl bootstrap system "$p"; do n=$((n + 1)); [ $n -ge 5 ] && exit 1; sleep 1; done
        done
        """
        runPrivilegedScript(script) { ok in
            if ok { self.helperInstalled = true; self.helperOutdated = false }
        }
    }

    func removeHelper() {
        let script = """
        for l in \(Self.applyLabel) \(Self.samplerLabel); do /bin/launchctl bootout system/$l 2>/dev/null || true; done
        /sbin/pfctl -a com.apple/rat -F all >/dev/null 2>&1 || true
        rm -f \(Self.shellQuote(Self.statusPath)) \(Self.shellQuote(Self.proxiedPath)) \(Self.shellQuote(Self.plistPath(Self.applyLabel))) \(Self.shellQuote(Self.plistPath(Self.samplerLabel))) \(Self.shellQuote(Self.helperPath)) \(Self.shellQuote(Self.enforcerPath))
        """
        runPrivilegedScript(script) { ok in
            if ok { self.helperInstalled = false; self.helperOutdated = false; self.status = nil }
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
        // Tests and demo mode (UI tests click through Settings) must never install, update or remove the real helper.
        guard !Preferences.isTesting && !Preferences.isDemo else {
            lastError = "The firewall helper cannot be changed in demo mode or under tests."
            done(false)
            return
        }
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
