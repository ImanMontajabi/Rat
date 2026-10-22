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

public enum UnknownNetworkAction: Codable, Equatable, Sendable {
    case ask, doNothing, deactivate
    case activate(UUID)
}

/// Everything the rule engine persists.
public struct RuleSet: Codable, Equatable, Sendable {
    /// 2: unknown connections are allowed silently by default (version 1 asked).
    public var version = 2
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
    /// What to do on a network no trigger knows: ask, do nothing, or switch to / away from a profile.
    public var unknownNetworkAction = UnknownNetworkAction.ask

    /// `silent` is what happens to connections no rule covers: nil asks (alert mode).
    public static func standard(silent: Verdict? = .allow) -> RuleSet {
        let home = Profile(name: "Home", symbol: "house")
        var set = RuleSet(profiles: [home, Profile(name: "Work", symbol: "briefcase"), Profile(name: "Public Wi-Fi", symbol: "wifi")],
                          groups: [], triggers: [], rules: [], activeProfileID: home.id)
        set.silentVerdict = silent
        return set
    }

    enum CodingKeys: String, CodingKey {
        case version, profiles, groups, triggers, rules, activeProfileID, markNewRulesAsUnapproved, silentVerdict, automaticProfileSwitching, unknownNetworkAction
    }

    public init(from d: Decoder) throws {
        let c = try d.container(keyedBy: CodingKeys.self)
        version = try c.decodeIfPresent(Int.self, forKey: .version) ?? 1
        profiles = try c.decode([Profile].self, forKey: .profiles)
        groups = try c.decodeIfPresent([RuleGroup].self, forKey: .groups) ?? []
        triggers = try c.decodeIfPresent([NetworkTrigger].self, forKey: .triggers) ?? []
        rules = try c.decodeIfPresent([Rule].self, forKey: .rules) ?? []
        activeProfileID = try c.decode(UUID.self, forKey: .activeProfileID)
        markNewRulesAsUnapproved = try c.decodeIfPresent(Bool.self, forKey: .markNewRulesAsUnapproved) ?? false
        silentVerdict = try c.decodeIfPresent(Verdict.self, forKey: .silentVerdict)
        automaticProfileSwitching = try c.decodeIfPresent(Bool.self, forKey: .automaticProfileSwitching) ?? false
        unknownNetworkAction = try c.decodeIfPresent(UnknownNetworkAction.self, forKey: .unknownNetworkAction) ?? .ask
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
