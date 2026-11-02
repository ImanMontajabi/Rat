import Darwin
import Foundation

/// Safari's web apps (File > Add to Dock). Each one is a small bundle in ~/Applications (`X.app`: an Info.plist with
/// `CFBundleIdentifier` `com.apple.Safari.WebApp.<UUID>`, an icon, no executable) that macOS runs with one program for
/// all of them, `/System/Library/CoreServices/Web App.app/Contents/MacOS/Web App` (in Safari's cryptex), started as
/// `Web App --bundlepath ~/Applications/X.app … --bundleidentifier com.apple.Safari.WebApp.<UUID>`. That process is the
/// responsible process of the web app's WebKit processes, so WebKit.Networking, which holds its connections, would
/// otherwise be grouped with every other web app as one "Web App". The bundle path is read from the arguments of the
/// host process (`KERN_PROCARGS2`, the same for the app and the root daemon); nothing else of them is kept.
public enum SafariWebApp {
    /// Where the host program lives, under the system volume or Safari's cryptex (which SIP protects).
    static let hostSuffix = "/System/Library/CoreServices/Web App.app/Contents/MacOS/Web App"
    static let hostPrefixes = ["/System/Library/CoreServices/", "/System/Volumes/Preboot/Cryptexes/", "/System/Cryptexes/"]
    /// What every web app's bundle identifier starts with.
    public static let identifierPrefix = "com.apple.Safari.WebApp."

    /// Whether the path is the program that runs every Safari web app.
    public static func isHost(_ path: String) -> Bool {
        path.hasSuffix(hostSuffix) && hostPrefixes.contains(where: path.hasPrefix) && !path.contains("/../")
    }

    /// The web app a host process runs, from its arguments: the value of `--bundlepath`, when `--bundleidentifier`
    /// names a Safari web app and the path is an absolute `.app` bundle that holds no other bundle in its path.
    /// The path ends up in rules and in the daemon's newline-separated files, so a line break or `..` makes it nil.
    public static func bundle(arguments argv: [String]) -> String? {
        var path: String?, identifier: String?
        var i = 1
        while i < argv.count, argv[i] != "--" {
            if i + 1 < argv.count {
                if argv[i] == "--bundlepath" { path = argv[i + 1]; i += 2; continue }
                if argv[i] == "--bundleidentifier" { identifier = argv[i + 1]; i += 2; continue }
            }
            i += 1
        }
        guard let identifier, identifier.hasPrefix(identifierPrefix), identifier.count > identifierPrefix.count,
              var path, path.hasPrefix("/"), path.count <= 1024 else { return nil }
        while path.count > 1, path.hasSuffix("/") { path.removeLast() }
        let parts = path.split(separator: "/", omittingEmptySubsequences: false)
        guard path.hasSuffix(".app"), !parts.dropFirst().contains(where: { $0.isEmpty || $0 == "." || $0 == ".." }),
              !path.contains(where: { $0.isNewline || $0 == "\0" }),
              ProcessGrouping.bundleRoot(of: path) == path else { return nil }
        return path
    }

    /// The web app a process belongs to: its own when it is the host, else its responsible process's when that is
    /// the host (WebKit.Networking, WebContent, the content blocker loader). Nil for everything else.
    public static func bundle(pid: pid_t, path: String? = nil) -> String? {
        let own = path ?? ConnectionSampler.path(of: pid)
        let host = isHost(own) ? pid : ProcessGrouping.responsiblePID(of: pid)
        guard host == pid ? isHost(own) : isHost(ConnectionSampler.path(of: host)),
              let argv = ProcessArguments.arguments(pid: host) else { return nil }
        return bundle(arguments: argv)
    }

    /// Whether a bundle on disk is a Safari web app (its Info.plist names one).
    public static func isWebAppBundle(_ bundlePath: String) -> Bool {
        Bundle(path: bundlePath)?.bundleIdentifier?.hasPrefix(identifierPrefix) == true
    }
}
