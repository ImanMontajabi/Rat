import Foundation

public struct Profile: Codable, Identifiable, Hashable, Sendable {
    public var id: UUID
    public var name: String
    public var symbol: String
    public init(id: UUID = UUID(), name: String, symbol: String = "person.crop.circle") {
        self.id = id; self.name = name; self.symbol = symbol
    }
}

public struct RuleGroup: Codable, Identifiable, Hashable, Sendable {
    public var id: UUID
    public var name: String
    public var enabled: Bool
    public init(id: UUID = UUID(), name: String, enabled: Bool = true) { self.id = id; self.name = name; self.enabled = enabled }
}

/// Switches to `profileID` when the Mac joins the network with this signature
/// (an SSID, or "gateway:<ip>" when the SSID is not readable).
public struct NetworkTrigger: Codable, Identifiable, Hashable, Sendable {
    public var id: UUID
    public var signature: String
    public var name: String
    public var profileID: UUID
    public init(id: UUID = UUID(), signature: String, name: String, profileID: UUID) {
        self.id = id; self.signature = signature; self.name = name; self.profileID = profileID
    }
}

/// Everything the rule engine persists.
public struct RuleSet: Codable, Equatable, Sendable {
    public var version = 1
    public var profiles: [Profile]
    public var groups: [RuleGroup]
    public var triggers: [NetworkTrigger]
    public var rules: [Rule]
    public var activeProfileID: UUID
    /// New rules from alerts and imports wait for approval.
    public var markNewRulesAsUnapproved = false
    /// What to do with unknown connections: nil = ask (alert mode); a verdict = silent mode.
    public var silentVerdict: Verdict?
    public var automaticProfileSwitching = false

    public static func standard() -> RuleSet {
        let home = Profile(name: "Home", symbol: "house")
        return RuleSet(profiles: [home, Profile(name: "Work", symbol: "briefcase"), Profile(name: "Public Wi-Fi", symbol: "wifi")],
                       groups: [], triggers: [], rules: [], activeProfileID: home.id)
    }

    public init(profiles: [Profile], groups: [RuleGroup], triggers: [NetworkTrigger], rules: [Rule], activeProfileID: UUID) {
        self.profiles = profiles; self.groups = groups; self.triggers = triggers; self.rules = rules; self.activeProfileID = activeProfileID
    }
}

/// Portable rule file ("Export Rules…").
public struct RuleExport: Codable, Sendable {
    public var format = "rat-rules"
    public var version = 1
    public var groups: [RuleGroup]
    public var rules: [Rule]
    public init(groups: [RuleGroup], rules: [Rule]) { self.groups = groups; self.rules = rules }

    public func encoded() throws -> Data {
        let e = JSONEncoder()
        e.outputFormatting = [.prettyPrinted, .sortedKeys]
        e.dateEncodingStrategy = .iso8601
        return try e.encode(self)
    }

    public static func decode(_ data: Data) throws -> RuleExport {
        let d = JSONDecoder()
        d.dateDecodingStrategy = .iso8601
        if let x = try? d.decode(RuleExport.self, from: data), x.format == "rat-rules" { return x }
        // Bare array of rules (the v0.1 RuleStore format).
        return RuleExport(groups: [], rules: try d.decode([Rule].self, from: data))
    }
}
