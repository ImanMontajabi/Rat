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

    /// Whether the path is a system service that works on behalf of an app (WebKit's networking XPC service
    /// carries Safari's traffic), so the app it works for is found through the responsible process.
    public static func actsForOthers(_ path: String) -> Bool {
        path.contains(".xpc/") && ["/System/", "/usr/", "/Library/Apple/"].contains(where: path.hasPrefix)
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

    /// Path of the application a system helper works for, if it differs from the helper itself.
    public static func responsiblePath(of pid: pid_t) -> String? {
        let r = responsiblePID(of: pid)
        guard r != pid else { return nil }
        let p = ConnectionSampler.path(of: r)
        return p.hasPrefix("pid ") ? nil : p
    }
}
