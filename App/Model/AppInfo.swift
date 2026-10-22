import AppKit
import Security
import Darwin

/// Resolves a process path to the user-facing application it belongs to.
struct AppIdentity: Hashable {
    let id: String          // outermost .app path, "macOS", or the executable path
    let name: String
    let bundlePath: String?
    let isSystem: Bool
    var isExtension = false

    /// What rules refer to: the app bundle (extensions share their host app's rules), or the executable path.
    var ruleKey: String { bundlePath ?? id }

    static func resolve(processPath path: String, pid: Int32? = nil) -> AppIdentity {
        if let r = path.range(of: ".app/") ?? (path.hasSuffix(".app") ? path.range(of: ".app", options: .backwards) : nil) {
            let bundle = String(path[..<r.upperBound]).trimmingSuffix("/")
            let name = FileManager.default.displayName(atPath: bundle).replacingOccurrences(of: ".app", with: "")
            // App extensions (.appex) are listed separately from their host app, like Little Snitch's "EXT" rows.
            if path.contains(".appex/") { return AppIdentity(id: bundle + "#ext", name: name, bundlePath: bundle, isSystem: false, isExtension: true) }
            return AppIdentity(id: bundle, name: name, bundlePath: bundle, isSystem: false)
        }
        let systemPrefixes = ["/System/", "/usr/", "/sbin/", "/bin/", "/Library/Apple/", "/private/var/db/"]
        if systemPrefixes.contains(where: path.hasPrefix) {
            return AppIdentity(id: "macOS", name: "macOS", bundlePath: nil, isSystem: true)
        }
        // Versioned CLI binaries ("…/claude/versions/2.1.308") belong to the tool, not to a version number.
        let base = (path as NSString).lastPathComponent
        if base.range(of: #"^\d[\d.]*$"#, options: .regularExpression) != nil {
            let parent = (path as NSString).deletingLastPathComponent
            var owner = parent
            if (parent as NSString).lastPathComponent == "versions" { owner = (parent as NSString).deletingLastPathComponent }
            let name = (owner as NSString).lastPathComponent
            if !name.isEmpty { return AppIdentity(id: owner, name: name, bundlePath: nil, isSystem: false) }
        }
        return AppIdentity(id: path, name: base, bundlePath: nil, isSystem: false)
    }

    @MainActor static var iconCache: [String: NSImage] = [:]

    @MainActor var icon: NSImage {
        if let c = Self.iconCache[id] { return c }
        let img: NSImage
        if let bundlePath { img = NSWorkspace.shared.icon(forFile: bundlePath) }
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
