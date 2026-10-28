import Foundation

/// One spelling of a program's path, for comparing paths. Parts of macOS are loaded from cryptexes, so one program has
/// several names: the kernel (`proc_pidpath`, what the root daemon reads) says
/// `/System/Volumes/Preboot/Cryptexes/Incoming/OS/System/Library/…` for WebKit's and Safari's helpers, or
/// `…/Cryptexes/OS/…` after a restart, while `ps`, lsof and the symlinks say `/System/Library/…`. Safari's own
/// cryptex is `/System/Volumes/Preboot/Cryptexes/App/…` or `/System/Cryptexes/App/…`. A rule made from one name has
/// to match a process seen under another, so rules and the daemon compare paths in this form.
public enum ProgramPath {
    static let osCryptexes = ["/System/Volumes/Preboot/Cryptexes/Incoming/OS/", "/System/Volumes/Preboot/Cryptexes/OS/",
                              "/private/preboot/Cryptexes/Incoming/OS/", "/private/preboot/Cryptexes/OS/", "/System/Cryptexes/OS/"]
    static let appCryptexes = ["/System/Volumes/Preboot/Cryptexes/Incoming/App/", "/System/Volumes/Preboot/Cryptexes/App/",
                               "/private/preboot/Cryptexes/Incoming/App/", "/private/preboot/Cryptexes/App/"]

    /// The OS cryptex's programs under the paths they are started by (`/System/Library/…`), the App cryptex's under
    /// `/System/Cryptexes/App/…`; every other path as it is.
    public static func canonical(_ path: String) -> String {
        guard path.hasPrefix("/System/Volumes/Preboot/Cryptexes/") || path.hasPrefix("/private/preboot/Cryptexes/") || path.hasPrefix("/System/Cryptexes/OS/") else { return path }
        for p in osCryptexes where path.hasPrefix(p) { return "/" + path.dropFirst(p.count) }
        for p in appCryptexes where path.hasPrefix(p) { return "/System/Cryptexes/App/" + path.dropFirst(p.count) }
        return path
    }

    /// Whether `path` is `prefix` or inside it, whichever names they use.
    public static func inside(_ path: String, _ prefix: String) -> Bool {
        let a = canonical(path), b = canonical(prefix)
        return a == b || a.hasPrefix(b + "/")
    }

    public static func same(_ a: String, _ b: String) -> Bool { a == b || canonical(a) == canonical(b) }
}
