import Darwin
import Foundation

/// Which application a process belongs to. Shared by the app and the root enforcer so both agree.
public enum ProcessGrouping {
    /// The outermost application bundle in a path: a `.app`, or Steam's `Steam.AppBundle` wrapper.
    /// Helpers (Chrome Helper, Steam Helper, Firefox plugin-container) live inside their app and group with it.
    public static func bundleRoot(of path: String) -> String? {
        var best: Range<String.Index>?
        for marker in [".app/", ".AppBundle/"] {
            if let r = path.range(of: marker), best == nil || r.lowerBound < best!.lowerBound { best = r }
        }
        if best == nil {
            for suffix in [".app", ".AppBundle"] where path.hasSuffix(suffix) { best = path.range(of: suffix, options: .backwards) }
        }
        guard let r = best else { return nil }
        var root = String(path[..<r.upperBound])
        if root.hasSuffix("/") { root.removeLast() }
        return root
    }

    /// Programs an app installs outside its bundle and runs from there. Windscribe's root helper copies its tunnels
    /// (`windscribeamneziawg`, `windscribeopenvpn`, `windscribewstunnel`, `windscribectrld`) into
    /// /Library/Application Support/Windscribe/bin. They belong to the app in the list and when it is denied.
    static let companions: [(prefix: String, app: String)] = [
        ("/Library/Application Support/Windscribe/", "/Applications/Windscribe.app"),
        ("/Library/PrivilegedHelperTools/com.windscribe.", "/Applications/Windscribe.app"),
    ]

    /// The app a program installed outside its bundle belongs to (see `companions`).
    public static func companionApp(of path: String) -> String? {
        companions.first { path.hasPrefix($0.prefix) }?.app
    }

    /// Whether the path is a system service that works on behalf of an app (WebKit's networking XPC service
    /// carries Safari's traffic), so the app it works for is found through the responsible process.
    public static func actsForOthers(_ path: String) -> Bool {
        path.contains(".xpc/") && ["/System/", "/usr/", "/Library/Apple/"].contains(where: path.hasPrefix)
    }

    /// The app a process belongs to in Rat's list: what its rules name (`ruleKey`).
    public enum Owner: Equatable, Sendable {
        /// An application bundle (`isExtension`: the process runs from an app extension inside it).
        case app(bundle: String, isExtension: Bool)
        /// The `macOS` row: system services.
        case system
        /// A command-line tool or other program outside a bundle (its path, or a versioned tool's folder).
        case tool(String)

        public var ruleKey: String {
            switch self {
            case .app(let bundle, _): bundle
            case .system: "macOS"
            case .tool(let path): path
            }
        }
    }

    static let systemPrefixes = ["/System/", "/usr/", "/sbin/", "/bin/", "/Library/Apple/", "/private/var/db/"]

    /// Which app a process belongs to, the same for the app's list and the root daemon. `responsiblePath` is asked
    /// only for a system service that works for others.
    public static func owner(of path: String, responsiblePath: () -> String?) -> Owner {
        // System services that work for an app (Safari's WebKit networking process) belong to that app.
        if actsForOthers(path), let owner = responsiblePath(), let bundle = bundleRoot(of: owner) {
            return .app(bundle: bundle, isExtension: owner.contains(".appex/"))
        }
        // A program the app installed outside its bundle (Windscribe's tunnels) belongs to the app.
        if let bundle = bundleRoot(of: path) ?? companionApp(of: path) { return .app(bundle: bundle, isExtension: path.contains(".appex/")) }
        if systemPrefixes.contains(where: path.hasPrefix) { return .system }
        // Versioned CLI binaries ("…/claude/versions/2.1.308") belong to the tool, not to a version number.
        let base = (path as NSString).lastPathComponent
        if base.range(of: #"^\d[\d.]*$"#, options: .regularExpression) != nil {
            let parent = (path as NSString).deletingLastPathComponent
            var owner = parent
            if (parent as NSString).lastPathComponent == "versions" { owner = (parent as NSString).deletingLastPathComponent }
            if !(owner as NSString).lastPathComponent.isEmpty { return .tool(owner) }
        }
        return .tool(path)
    }

    private typealias ResponsibleFn = @convention(c) (pid_t) -> pid_t
    private static let responsibleFn: ResponsibleFn? = {
        // RTLD_DEFAULT is (void *)-2 on Darwin.
        guard let sym = dlsym(UnsafeMutableRawPointer(bitPattern: -2), "responsibility_get_pid_responsible_for_pid") else { return nil }
        return unsafeBitCast(sym, to: ResponsibleFn.self)
    }()

    /// The process macOS holds responsible for `pid` (launchd's attribution used by Activity Monitor), or `pid` itself.
    public static func responsiblePID(of pid: pid_t) -> pid_t {
        guard let fn = responsibleFn else { return pid }
        let r = fn(pid)
        return r > 0 ? r : pid
    }

    /// The parent process, or 0 when it cannot be read.
    public static func parentPID(of pid: pid_t) -> pid_t {
        var info = proc_bsdinfo()
        let n = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, Int32(MemoryLayout<proc_bsdinfo>.size))
        return n == Int32(MemoryLayout<proc_bsdinfo>.size) ? pid_t(info.pbi_ppid) : 0
    }

    /// The nearest application that started a command-line process (`git-remote-https` ← `git` ← `zsh` ← Warp):
    /// the first parent inside an app bundle, or nil when the chain reaches launchd first. Display only: rules and
    /// the daemon still treat the tool as its own app.
    public static func launchingApp(of pid: pid_t, maxDepth: Int = 16, parent: (pid_t) -> pid_t = parentPID(of:),
                                    path: (pid_t) -> String = ConnectionSampler.path(of:)) -> (pid: pid_t, path: String)? {
        var current = parent(pid)
        for _ in 0..<maxDepth where current > 1 {
            let p = path(current)
            if bundleRoot(of: p) != nil { return (current, p) }
            current = parent(current)
        }
        return nil
    }

    /// Path of the application a system helper works for, if it differs from the helper itself.
    public static func responsiblePath(of pid: pid_t) -> String? {
        let r = responsiblePID(of: pid)
        guard r != pid else { return nil }
        let p = ConnectionSampler.path(of: r)
        return p.hasPrefix("pid ") ? nil : p
    }
}
