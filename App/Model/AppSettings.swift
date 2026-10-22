import SwiftUI
import UserNotifications
import RatFilterCore

/// User-facing preferences (the Settings window), stored in UserDefaults.
@MainActor
final class AppSettings: ObservableObject {
    static let shared = AppSettings()

    enum RateUnit: String, CaseIterable, Identifiable { case bytes = "Bytes/s", bits = "Bits/s"; var id: String { rawValue } }
    enum RateVisibility: String, CaseIterable, Identifiable { case automatic = "Automatic", always = "Always", never = "Never"; var id: String { rawValue } }
    enum GroupBy: String, CaseIterable, Identifiable { case process = "Process", domain = "Domain", country = "Country"; var id: String { rawValue } }
    enum SortKey: String, CaseIterable, Identifiable { case recent = "Recent Activity", name = "Name", traffic = "Traffic"; var id: String { rawValue } }

    private let defaults = UserDefaults.standard

    // Menu bar (Control Center)
    @Published var showInMenuBar: Bool { didSet { defaults.set(showInMenuBar, forKey: "showInMenuBar") } }
    @Published var numericRates: Bool { didSet { defaults.set(numericRates, forKey: "numericRates") } }
    @Published var silentModeSymbol: Bool { didSet { defaults.set(silentModeSymbol, forKey: "silentModeSymbol") } }
    @Published var trafficRateUnit: RateUnit { didSet { defaults.set(trafficRateUnit.rawValue, forKey: "trafficRateUnit") } }

    // Alert
    @Published var confirmWithReturn: Bool { didSet { defaults.set(confirmWithReturn, forKey: "confirmWithReturn") } }
    @Published var alertTimeout: Int { didSet { defaults.set(alertTimeout, forKey: "alertTimeout") } }
    @Published var alertTimeoutAllows: Bool { didSet { defaults.set(alertTimeoutAllows, forKey: "alertTimeoutAllows") } }

    // Monitor
    @Published var includeLocalNetwork: Bool { didSet { defaults.set(includeLocalNetwork, forKey: "includeLocalNetwork") } }
    @Published var includeNetworkExtensions: Bool { didSet { defaults.set(includeNetworkExtensions, forKey: "includeNetworkExtensions") } }
    @Published var includeOtherUsers: Bool { didSet { defaults.set(includeOtherUsers, forKey: "includeOtherUsers") } }
    @Published var groupBy: GroupBy { didSet { defaults.set(groupBy.rawValue, forKey: "groupBy") } }
    @Published var sortKey: SortKey { didSet { defaults.set(sortKey.rawValue, forKey: "sortKey") } }
    @Published var floatOnTop: Bool { didSet { defaults.set(floatOnTop, forKey: "floatOnTop") } }
    @Published var additionalLocalRanges: String {
        didSet { defaults.set(additionalLocalRanges, forKey: "additionalLocalRanges"); LocalRanges.shared.set(additionalLocalRanges) }
    }

    // Notifications
    @Published var notifySilentConnections: Bool { didSet { defaults.set(notifySilentConnections, forKey: "notifySilentConnections") } }
    @Published var notifyProfileSwitch: Bool { didSet { defaults.set(notifyProfileSwitch, forKey: "notifyProfileSwitch") } }
    @Published var notifyAlertTimeout: Bool { didSet { defaults.set(notifyAlertTimeout, forKey: "notifyAlertTimeout") } }

    // Update
    @Published var autoCheckUpdates: Bool { didSet { defaults.set(autoCheckUpdates, forKey: "autoCheckUpdates") } }
    @Published var showPreReleases: Bool { didSet { defaults.set(showPreReleases, forKey: "showPreReleases") } }
    @Published var lastUpdateCheck: Date? { didSet { defaults.set(lastUpdateCheck, forKey: "lastUpdateCheck") } }
    @Published var lastUpdateCheckFailed: Bool { didSet { defaults.set(lastUpdateCheckFailed, forKey: "lastUpdateCheckFailed") } }

    // Advanced
    @Published var approveRulesAutomatically: Bool { didSet { defaults.set(approveRulesAutomatically, forKey: "approveRulesAutomatically") } }

    private init() {
        func bool(_ k: String, _ d: Bool) -> Bool { UserDefaults.standard.object(forKey: k) as? Bool ?? d }
        showInMenuBar = bool("showInMenuBar", true)
        numericRates = bool("numericRates", true)
        silentModeSymbol = bool("silentModeSymbol", true)
        trafficRateUnit = RateUnit(rawValue: UserDefaults.standard.string(forKey: "trafficRateUnit") ?? "") ?? .bytes
        confirmWithReturn = bool("confirmWithReturn", true)
        alertTimeout = UserDefaults.standard.integer(forKey: "alertTimeout")
        alertTimeoutAllows = bool("alertTimeoutAllows", false)
        includeLocalNetwork = bool("includeLocalNetwork", false)
        includeNetworkExtensions = bool("includeNetworkExtensions", false)
        includeOtherUsers = bool("includeOtherUsers", false)
        groupBy = GroupBy(rawValue: UserDefaults.standard.string(forKey: "groupBy") ?? "") ?? .process
        sortKey = SortKey(rawValue: UserDefaults.standard.string(forKey: "sortKey") ?? "") ?? .recent
        floatOnTop = bool("floatOnTop", false)
        additionalLocalRanges = UserDefaults.standard.string(forKey: "additionalLocalRanges") ?? ""
        notifySilentConnections = bool("notifySilentConnections", true)
        notifyProfileSwitch = bool("notifyProfileSwitch", true)
        notifyAlertTimeout = bool("notifyAlertTimeout", true)
        autoCheckUpdates = bool("autoCheckUpdates", true)
        showPreReleases = bool("showPreReleases", false)
        lastUpdateCheck = UserDefaults.standard.object(forKey: "lastUpdateCheck") as? Date
        lastUpdateCheckFailed = bool("lastUpdateCheckFailed", false)
        approveRulesAutomatically = bool("approveRulesAutomatically", true)
        LocalRanges.shared.set(additionalLocalRanges)
    }

    /// Rate formatted in the chosen unit, e.g. "1.2 MB/s" or "9.6 Mbit/s".
    func formatRate(_ bytesPerSecond: Double) -> String {
        switch trafficRateUnit {
        case .bytes:
            let f = ByteCountFormatter(); f.countStyle = .file; f.allowsNonnumericFormatting = false
            return f.string(fromByteCount: Int64(bytesPerSecond)) + "/s"
        case .bits:
            let bits = bytesPerSecond * 8
            for (unit, div) in [("Gbit/s", 1e9), ("Mbit/s", 1e6), ("kbit/s", 1e3)] where bits >= div { return String(format: "%.1f %@", bits / div, unit) }
            return "\(Int(bits)) bit/s"
        }
    }
}

/// Extra address ranges the user wants treated as the local network ("Additional IP Ranges in Local Network").
final class LocalRanges: @unchecked Sendable {
    static let shared = LocalRanges()
    private let lock = NSLock()
    private var ranges: [(base: UInt32, mask: UInt32)] = []

    /// Parses "10.5.0.0/16, 100.64.0.0/10" (comma, space or newline separated). Returns the entries that did not parse.
    @discardableResult
    func set(_ text: String) -> [String] {
        var bad: [String] = []
        var parsed: [(UInt32, UInt32)] = []
        for token in text.split(whereSeparator: { ", \n".contains($0) }) {
            if let r = Self.parse(String(token)) { parsed.append(r) } else { bad.append(String(token)) }
        }
        lock.withLock { ranges = parsed }
        return bad
    }

    func contains(_ address: String) -> Bool {
        var a = in_addr()
        guard inet_pton(AF_INET, address, &a) == 1 else { return false }
        let ip = UInt32(bigEndian: a.s_addr)
        return lock.withLock { ranges.contains { (ip & $0.mask) == $0.base } }
    }

    static func parse(_ s: String) -> (base: UInt32, mask: UInt32)? {
        let parts = s.split(separator: "/", omittingEmptySubsequences: false)
        guard parts.count <= 2 else { return nil }
        var a = in_addr()
        guard inet_pton(AF_INET, String(parts[0]), &a) == 1 else { return nil }
        let bits = parts.count == 2 ? Int(parts[1]) : 32
        guard let bits, (0...32).contains(bits) else { return nil }
        let mask: UInt32 = bits == 0 ? 0 : ~UInt32(0) << UInt32(32 - bits)
        return (UInt32(bigEndian: a.s_addr) & mask, mask)
    }
}

/// System notifications for the events listed in Settings > Notifications.
@MainActor
enum Notifier {
    static func requestAuthorization() {
        UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound]) { _, _ in }
    }

    static func post(title: String, body: String) {
        let c = UNMutableNotificationContent()
        c.title = title
        c.body = body
        UNUserNotificationCenter.current().add(UNNotificationRequest(identifier: UUID().uuidString, content: c, trigger: nil))
    }
}
