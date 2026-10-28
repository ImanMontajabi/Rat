import Foundation

/// What Rat hands the root daemon in `deny-rules.json` so it judges the sockets of denied processes and connections
/// itself, on every pass (every 3 ms), instead of waiting for Rat's 1.5 s pass: the active rules, the names Rat
/// found for addresses, the apps' code signatures and the user's local ranges. Whole-app denies stay in
/// `denied-apps.txt`. Only local ports are ever blocked from it, never a server's address.
public struct DaemonRules: Codable, Equatable, Sendable {
    public struct Signature: Codable, Equatable, Sendable {
        public var signingID: String?
        public var teamID: String?
        public init(signingID: String?, teamID: String?) { self.signingID = signingID; self.teamID = teamID }
    }

    public var version = 1
    /// The enabled rules of the active profile (`RuleEngine.activeRules`), allow rules included: they decide too.
    public var rules: [Rule]
    /// Address → the name Rat judged it by ("" when it has none). An address missing here is not named yet.
    public var names: [String: String]
    /// App (`ProcessGrouping.Owner.ruleKey`) → its code signature, for rules that name a signing ID or team.
    public var signatures: [String: Signature]
    /// Settings > Advanced's "Additional IP Ranges in Local Network" (see `LocalNetwork`).
    public var localRanges: String

    public init(rules: [Rule] = [], names: [String: String] = [:], signatures: [String: Signature] = [:], localRanges: String = "") {
        self.rules = rules; self.names = names; self.signatures = signatures; self.localRanges = localRanges
    }

    enum CodingKeys: String, CodingKey { case version, rules, names, signatures, localRanges }

    public init(from d: Decoder) throws {
        let c = try d.container(keyedBy: CodingKeys.self)
        version = try c.decodeIfPresent(Int.self, forKey: .version) ?? 1
        rules = try c.decodeIfPresent([Rule].self, forKey: .rules) ?? []
        names = try c.decodeIfPresent([String: String].self, forKey: .names) ?? [:]
        signatures = try c.decodeIfPresent([String: Signature].self, forKey: .signatures) ?? [:]
        localRanges = try c.decodeIfPresent(String.self, forKey: .localRanges) ?? ""
    }

    /// Deny rules the daemon can follow: those naming a process path, so it knows which processes to read. A deny for
    /// any process, or by code signature alone, is left to Rat's pass (it would mean reading every process).
    public var hasProcessDenies: Bool { rules.contains { $0.verdict == .deny && $0.processPath != nil } }

    public func encoded() throws -> Data {
        let e = JSONEncoder(); e.outputFormatting = [.sortedKeys]; e.dateEncodingStrategy = .iso8601
        return try e.encode(self)
    }

    public static func decode(_ data: Data) -> DaemonRules? {
        let d = JSONDecoder(); d.dateDecodingStrategy = .iso8601
        return try? d.decode(DaemonRules.self, from: data)
    }
}

/// Judges one socket the way Rat's pass judges its connection (`RuleEngine.decide`), for the root daemon. It denies
/// only what Rat's rules certainly deny: while Rat has not named a server, a rule for a name counts as matching it
/// when it allows, and as not matching when it denies (`RuleEngine.decide(_:unknown:)`); Rat's pass still judges
/// the connection once the name is known.
public final class SocketJudge: @unchecked Sendable {
    private let engine: RuleEngine
    private let names: [String: String]
    private let signatures: [String: DaemonRules.Signature]
    private let local = LocalRanges()
    /// What a deny rule can match: the app or program it names, and the one executable when it is for one process
    /// (or one connection of it). A socket is denied only by a deny rule that matches it (the default is allow), so a
    /// process none of these can match is never read.
    public struct Watch: Hashable, Comparable, Sendable {
        public var path: String
        public var executable: String?
        public static func < (a: Watch, b: Watch) -> Bool { (a.path, a.executable ?? "") < (b.path, b.executable ?? "") }
    }

    /// The processes deny rules can match: a process is read only when one of these covers it.
    public let watchList: [Watch]

    public init(_ d: DaemonRules) {
        // The file holds the rules active in Rat's profile and groups already; the daemon has neither.
        engine = RuleEngine(rules: d.rules.filter(\.enabled).map { var r = $0; r.profileID = nil; r.groupID = nil; return r }, defaultVerdict: .allow)
        names = d.names
        signatures = d.signatures
        local.set(d.localRanges)
        watchList = Array(Set(d.rules.compactMap { r in r.enabled && r.verdict == .deny ? r.processPath.map { Watch(path: $0, executable: r.executable) } : nil })).sorted()
    }

    private static func inside(_ path: String, _ prefix: String) -> Bool { ProgramPath.inside(path, prefix) }

    /// Whether a process (its app's `ruleKey` and its own executable) may be denied by a rule, so its sockets are read.
    /// A ✗ on one of Safari's helpers reads that helper, not Safari's other two dozen processes every 3 ms.
    public func watches(app: String, executable: String) -> Bool {
        watchList.contains { w in
            (Self.inside(app, w.path) || Self.inside(executable, w.path)) && w.executable.map { Self.inside(executable, $0) } ?? true
        }
    }

    /// Whether the rules deny a socket. `address` is "" (and `port` 0) for a socket not connected to a server.
    public func denies(app: String, executable: String, address: String, port: Int, proto: Connection.Proto) -> Bool {
        let sig = signatures[app]
        var unknown: Rule.Unknown = sig == nil ? [.signing] : []
        let connected = !address.isEmpty && port != 0
        var host: String?
        if !connected { unknown.insert(.remote) }
        else if let n = names[address] { host = n.isEmpty ? nil : n }
        else { unknown.insert(.host) }
        let c = Connection(process: ProcessIdentity(signingID: sig?.signingID, teamID: sig?.teamID, path: app), executable: executable,
                           host: host, address: connected ? address : "", port: connected ? port : 0, proto: proto)
        let d = engine.decide(c, unknown: unknown)
        guard d.verdict == .deny, let rule = d.rule else { return false }
        // Rat's pass does not judge connections inside the local network by rules from alerts or the Rules window;
        // a ✗ in the process list covers them, as an app's ✗ does.
        if connected, rule.effectiveListLevel == nil, LocalNetwork.contains(address, extra: local) { return false }
        return true
    }
}
