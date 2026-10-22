import AppKit
import os

private let logger = Logger(subsystem: "com.imanmontajabi.Rat", category: "update")

/// Asks the GitHub Releases API whether a newer version exists. Runs only when the user chooses it.
enum UpdateChecker {
    static let repo = "ImanMontajabi/Rat"

    /// True when `latest` is a higher dotted version than `current` ("v0.3.0" vs "0.2.0").
    static func isNewer(_ latest: String, than current: String) -> Bool {
        func parts(_ s: String) -> [Int] { s.trimmingCharacters(in: CharacterSet(charactersIn: "vV")).split(separator: ".").map { Int($0) ?? 0 } }
        let a = parts(latest), b = parts(current)
        for i in 0..<max(a.count, b.count) {
            let x = i < a.count ? a[i] : 0, y = i < b.count ? b[i] : 0
            if x != y { return x > y }
        }
        return false
    }

    /// Silent check at launch when automatic checks are on and the last one is over a day old.
    @MainActor static func checkIfDue() async {
        let settings = AppSettings.shared
        guard settings.autoCheckUpdates else { return }
        if let last = settings.lastUpdateCheck, Date().timeIntervalSince(last) < 86_400 { return }
        if let release = await latest(includePreReleases: settings.showPreReleases),
           isNewer(release.tag, than: Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "0") {
            present(release, current: Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "0")
        }
    }

    struct Release { var tag: String; var url: String; var prerelease: Bool }

    /// The newest published release (optionally including pre-releases). Records the attempt in the settings.
    @MainActor static func latest(includePreReleases: Bool) async -> Release? {
        let settings = AppSettings.shared
        do {
            var req = URLRequest(url: URL(string: "https://api.github.com/repos/\(repo)/releases")!)
            req.setValue("application/vnd.github+json", forHTTPHeaderField: "Accept")
            let (data, _) = try await URLSession.shared.data(for: req)
            guard let list = try JSONSerialization.jsonObject(with: data) as? [[String: Any]] else { throw URLError(.cannotParseResponse) }
            settings.lastUpdateCheck = Date(); settings.lastUpdateCheckFailed = false
            return list.compactMap { j -> Release? in
                guard j["draft"] as? Bool != true, let tag = j["tag_name"] as? String else { return nil }
                let pre = j["prerelease"] as? Bool ?? false
                guard includePreReleases || !pre else { return nil }
                return Release(tag: tag, url: j["html_url"] as? String ?? "https://github.com/\(repo)/releases", prerelease: pre)
            }.max { !isNewer($1.tag, than: $0.tag) ? false : true }
        } catch {
            logger.error("update check failed: \(error.localizedDescription, privacy: .public)")
            settings.lastUpdateCheck = Date(); settings.lastUpdateCheckFailed = true
            return nil
        }
    }

    @MainActor private static func present(_ r: Release, current: String) {
        let alert = NSAlert()
        alert.messageText = "Rat \(r.tag) is available"
        alert.informativeText = "You have \(current)."
        alert.addButton(withTitle: "Open Download Page"); alert.addButton(withTitle: "Later")
        if alert.runModal() == .alertFirstButtonReturn, let u = URL(string: r.url) { NSWorkspace.shared.open(u) }
    }

    /// "Check Now": always answers.
    @MainActor static func check() async {
        let current = Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "0"
        let release = await latest(includePreReleases: AppSettings.shared.showPreReleases)
        if AppSettings.shared.lastUpdateCheckFailed {
            let alert = NSAlert(); alert.messageText = "Could not check for updates"; alert.informativeText = "Check your internet connection and try again."; alert.runModal(); return
        }
        guard let release else { let a = NSAlert(); a.messageText = "No releases found"; a.runModal(); return }
        if isNewer(release.tag, than: current) { present(release, current: current) }
        else { let a = NSAlert(); a.messageText = "Rat is up to date"; a.informativeText = "Version \(current) is the latest."; a.runModal() }
    }
}
