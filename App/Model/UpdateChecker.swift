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

    @MainActor static func check() async {
        let current = Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "0"
        let alert = NSAlert()
        do {
            var req = URLRequest(url: URL(string: "https://api.github.com/repos/\(repo)/releases/latest")!)
            req.setValue("application/vnd.github+json", forHTTPHeaderField: "Accept")
            let (data, _) = try await URLSession.shared.data(for: req)
            guard let j = try JSONSerialization.jsonObject(with: data) as? [String: Any], let tag = j["tag_name"] as? String else {
                alert.messageText = "No releases found"
                alert.informativeText = "There is no published release yet."
                alert.runModal(); return
            }
            if isNewer(tag, than: current) {
                alert.messageText = "Rat \(tag) is available"
                alert.informativeText = "You have \(current)."
                alert.addButton(withTitle: "Open Download Page"); alert.addButton(withTitle: "Later")
                if alert.runModal() == .alertFirstButtonReturn, let u = URL(string: j["html_url"] as? String ?? "https://github.com/\(repo)/releases") { NSWorkspace.shared.open(u) }
            } else {
                alert.messageText = "Rat is up to date"
                alert.informativeText = "Version \(current) is the latest."
                alert.runModal()
            }
        } catch {
            logger.error("update check failed: \(error.localizedDescription, privacy: .public)")
            alert.messageText = "Could not check for updates"
            alert.informativeText = error.localizedDescription
            alert.runModal()
        }
    }
}
