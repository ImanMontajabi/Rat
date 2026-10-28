import AppKit
import Security
import Darwin
import RatMonitor

/// Resolves a process path to the user-facing application it belongs to.
struct AppIdentity: Hashable {
    let id: String          // outermost .app path, "macOS", or the executable path
    let name: String
    let bundlePath: String?
    let isSystem: Bool
    var isExtension = false

    /// What rules refer to: the app bundle (extensions share their host app's rules), or the executable path.
    var ruleKey: String { bundlePath ?? id }

    /// The grouping itself is `ProcessGrouping.owner`, which the root daemon uses too, so both name the same app.
    static func resolve(processPath path: String, pid: Int32? = nil) -> AppIdentity {
        switch ProcessGrouping.owner(of: path, responsiblePath: { pid.flatMap(ProcessGrouping.responsiblePath(of:)) }) {
        case .app(let bundle, let isExtension):
            // "Steam.AppBundle" holds Steam's client and helpers; other bundles show the name Finder shows.
            let name = bundle.hasSuffix(".AppBundle")
                ? ((bundle as NSString).lastPathComponent as NSString).deletingPathExtension
                : FileManager.default.displayName(atPath: bundle).replacingOccurrences(of: ".app", with: "")
            // App extensions (.appex) are listed separately from their host app, like Little Snitch's "EXT" rows.
            if isExtension { return AppIdentity(id: bundle + "#ext", name: name, bundlePath: bundle, isSystem: false, isExtension: true) }
            return AppIdentity(id: bundle, name: name, bundlePath: bundle, isSystem: false)
        case .system:
            return AppIdentity(id: "macOS", name: "macOS", bundlePath: nil, isSystem: true)
        case .tool(let path):
            return AppIdentity(id: path, name: (path as NSString).lastPathComponent, bundlePath: nil, isSystem: false)
        }
    }

    @MainActor static var mainProcessCache: [String: String?] = [:]

    /// The executable the app runs as ("Google Chrome"). A connection held by another process (a helper) is shown
    /// "via <process>". Nil for the "macOS" row, where every service is shown by name.
    @MainActor var mainProcessName: String? {
        if isSystem { return nil }
        if let c = Self.mainProcessCache[id] { return c }
        let name = bundlePath.map { Bundle(path: $0)?.executableURL?.lastPathComponent } ?? (id as NSString).lastPathComponent
        Self.mainProcessCache[id] = .some(name)
        return name
    }

    @MainActor static var iconCache: [String: NSImage] = [:]

    @MainActor var icon: NSImage {
        if let c = Self.iconCache[id] { return c }
        let img: NSImage
        if let bundlePath, bundlePath.hasSuffix(".AppBundle"), FileManager.default.fileExists(atPath: "/Applications/\(name).app") {
            img = NSWorkspace.shared.icon(forFile: "/Applications/\(name).app")
        } else if let bundlePath { img = NSWorkspace.shared.icon(forFile: bundlePath) }
        else if isSystem, let sys = NSImage(systemSymbolName: "apple.logo", accessibilityDescription: nil) { img = sys }
        else { img = NSWorkspace.shared.icon(forFile: id.replacingOccurrences(of: "#ext", with: "")) }
        Self.iconCache[id] = img
        return img
    }

    /// Code-signing identifier and team for the bundle or executable.
    func signing() -> (identifier: String?, team: String?) {
        var code: SecStaticCode?
        guard SecStaticCodeCreateWithPath(URL(fileURLWithPath: bundlePath ?? id) as CFURL, [], &code) == errSecSuccess, let code else { return (nil, nil) }
        var info: CFDictionary?
        guard SecCodeCopySigningInformation(code, SecCSFlags(rawValue: kSecCSSigningInformation), &info) == errSecSuccess,
              let d = info as? [String: Any] else { return (nil, nil) }
        return (d[kSecCodeInfoIdentifier as String] as? String, d[kSecCodeInfoTeamIdentifier as String] as? String)
    }
}

private extension String {
    func trimmingSuffix(_ s: String) -> String { hasSuffix(s) ? String(dropLast(s.count)) : self }
}

/// System services that work for many apps at once. Their sockets belong to the service and the service is its own
/// responsible process, so nothing on the socket says which app asked. Rat shows them as such instead of guessing.
enum SharedServices {
    private static let notes: [String: String] = [
        "mDNSResponder": "DNS and Bonjour for every app. Which app asked for a name cannot be seen: that needs a DNS proxy (a Network Extension), which Rat cannot install.",
        "nsurlsessiond": "Background downloads and uploads on behalf of apps.",
        "apsd": "Push notifications for every app.",
        "trustd": "Certificate checks for every app.",
        "cloudd": "iCloud sync on behalf of apps.",
        "networkserviceproxy": "iCloud Private Relay for apps that use it.",
        "com.apple.WebKit.Networking": "Web content for an app that macOS did not name.",
    ]

    /// What the service does for others, or nil for a service that works for itself.
    static func note(for process: String) -> String? { notes[process] }
}

