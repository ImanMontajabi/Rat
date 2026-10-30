import Foundation

/// Evaluates connections against the rules of the active profile.
public final class RuleEngine: @unchecked Sendable {
    private let lock = NSLock()
    private var set: RuleSet
    public var defaultVerdict: Verdict {
        get { lock.withLock { set.silentVerdict ?? .ask } }
        set { lock.withLock { set.silentVerdict = newValue == .ask ? nil : newValue } }
    }

    public init(rules: [Rule] = [], defaultVerdict: Verdict = .ask) {
        var s = RuleSet.standard()
        s.rules = rules
        s.silentVerdict = defaultVerdict == .ask ? nil : defaultVerdict
        set = s
    }

    public init(ruleSet: RuleSet) { set = ruleSet }

    public var ruleSet: RuleSet {
        get { lock.withLock { set } }
        set { lock.withLock { self.set = newValue } }
    }

    public var allRules: [Rule] { lock.withLock { set.rules } }
    public func setRules(_ new: [Rule]) { lock.withLock { set.rules = new } }
    public func add(_ rule: Rule) { lock.withLock { set.rules.append(rule) } }
    public func remove(id: UUID) { lock.withLock { set.rules.removeAll { $0.id == id } } }

    /// The enabled rules that can apply right now (what the root daemon is handed, see `DaemonRules`).
    public var activeRules: [Rule] { active(lock.withLock { set }).filter(\.enabled) }

    /// Rules that can apply right now: active profile, enabled group.
    private func active(_ s: RuleSet) -> [Rule] {
        let disabled = Set(s.groups.filter { !$0.enabled }.map(\.id))
        return s.rules.filter { ($0.profileID == nil || $0.profileID == s.activeProfileID) && !($0.groupID.map(disabled.contains) ?? false) }
    }

    /// The winning rule, if any. Specificity first, then deny over allow, then newest.
    public func matchingRule(_ c: Connection) -> Rule? {
        let snapshot = lock.withLock { set }
        return active(snapshot).filter { $0.matches(c) }.max(by: Self.weaker)
    }

    public func evaluate(_ c: Connection) -> Verdict {
        matchingRule(c)?.verdict ?? lock.withLock { set.silentVerdict ?? .ask }
    }

    /// What the rules decide for a connection, and the rule that decided (nil: Silent Mode or Ask).
    public struct Decision: Equatable, Sendable {
        public var verdict: Verdict
        public var rule: Rule?
        public init(verdict: Verdict, rule: Rule?) { self.verdict = verdict; self.rule = rule }
    }

    /// "Only through a VPN" (`Rule.requireVPN`) decides first: a connection that leaves outside a tunnel is denied
    /// whatever ✓ the app or its rows have, or the kill switch would let it through. Then the process list's ✗/✓
    /// decide, the narrowest level first: one connection's, then one process's, then the app's. They win over the
    /// app's other rules (alerts made many narrow ones, one domain or address at a time), but a ✓ does not lift a deny rule for any process. Without a ✗/✓ the most specific rule decides
    /// (`matchingRule`), or Silent Mode.
    public func decide(_ c: Connection) -> Decision { decide(c, unknown: []) }

    /// The decision when part of the connection is `unknown` (the root daemon judging a socket before Rat has named
    /// its server), made so that it is a deny only when every value the unknown part could take is denied: rules
    /// that do not deny count as matching whatever it is, deny rules only when they need none of it. Matching more
    /// non-deny rules and fewer deny rules never turns a decision into a deny, so a deny here is a deny for sure.
    public func decide(_ c: Connection, unknown: Rule.Unknown) -> Decision {
        let snapshot = lock.withLock { set }
        let matching = active(snapshot).filter { $0.matches(c, assuming: $0.verdict == .deny ? [] : unknown) }
        if let vpnOnly = matching.filter({ $0.requireVPN && $0.verdict == .deny }).max(by: Self.weaker) {
            return Decision(verdict: .deny, rule: vpnOnly)
        }
        let listed = matching.filter { $0.effectiveListLevel != nil }.max { a, b in
            if a.effectiveListLevel! != b.effectiveListLevel! { return a.effectiveListLevel! < b.effectiveListLevel! }
            return Self.weaker(a, b)
        }
        if let l = listed {
            if l.verdict == .allow, let any = matching.filter(\.isForAnyProcess).max(by: Self.weaker), any.verdict == .deny {
                return Decision(verdict: .deny, rule: any)
            }
            return Decision(verdict: l.verdict, rule: l)
        }
        let m = matching.max(by: Self.weaker)
        return Decision(verdict: m?.verdict ?? snapshot.silentVerdict ?? .ask, rule: m)
    }

    /// Ordering of matching rules: specificity first, then deny over allow, then newest.
    static func weaker(_ a: Rule, _ b: Rule) -> Bool {
        if a.specificity != b.specificity { return a.specificity < b.specificity }
        if (a.verdict == .deny) != (b.verdict == .deny) { return a.verdict != .deny }
        return a.createdAt < b.createdAt
    }

    /// Merge imported rules. Imported rules arrive unapproved and disabled when requested; ids already present are skipped.
    @discardableResult
    public func importRules(_ export: RuleExport, markUnapproved: Bool) -> Int {
        lock.withLock {
            let known = Set(set.rules.map(\.id))
            let knownGroups = Set(set.groups.map(\.id))
            for g in export.groups where !knownGroups.contains(g.id) { set.groups.append(g) }
            var added = 0
            for var r in export.rules where !known.contains(r.id) {
                if markUnapproved { r.approved = false; r.enabled = false }
                r.lifetime = .forever
                // Profiles are local to a machine: a rule scoped to a profile this set doesn't have would never fire.
                if let pid = r.profileID, !set.profiles.contains(where: { $0.id == pid }) { r.profileID = nil }
                if let gid = r.groupID, !set.groups.contains(where: { $0.id == gid }) { r.groupID = nil }
                set.rules.append(r); added += 1
            }
            return added
        }
    }

    public func exportRules(includeUnapproved: Bool = true) -> RuleExport {
        lock.withLock {
            RuleExport(groups: set.groups, rules: set.rules.filter { $0.lifetime == .forever && (includeUnapproved || $0.approved) })
        }
    }

    /// Profile that an automatic-switching trigger selects for this network, if any.
    public func profile(forNetwork signature: String) -> UUID? {
        lock.withLock { set.triggers.first { $0.signature == signature }?.profileID }
    }

    /// Drop session-only rules (called when the app quits).
    public func purgeSessionRules() { lock.withLock { set.rules.removeAll { $0.lifetime != .forever } } }
}

/// JSON persistence for the rule set.
public struct RuleStore {
    public let url: URL
    public init(url: URL) { self.url = url }

    /// Loads a full rule set, upgrading a v0.1 bare rule array if that is what is on disk.
    public func loadSet() throws -> RuleSet {
        guard FileManager.default.fileExists(atPath: url.path) else { return RuleSet.standard() }
        let data = try Data(contentsOf: url)
        let d = JSONDecoder(); d.dateDecodingStrategy = .iso8601
        if var s = try? d.decode(RuleSet.self, from: data) {
            // Version 1 files asked about every unknown connection; version 2 allows them silently.
            if s.version < 2 { s.version = 2; s.silentVerdict = .allow }
            return s
        }
        var s = RuleSet.standard()
        s.rules = try d.decode([Rule].self, from: data)
        return s
    }

    public func saveSet(_ set: RuleSet) throws {
        var s = set
        s.rules = s.rules.filter { $0.lifetime == .forever }
        let e = JSONEncoder(); e.outputFormatting = [.prettyPrinted, .sortedKeys]; e.dateEncodingStrategy = .iso8601
        try e.encode(s).write(to: url, options: .atomic)
    }

    // v0.1 API
    public func load() throws -> [Rule] { try loadSet().rules }
    public func save(_ rules: [Rule]) throws { var s = (try? loadSet()) ?? RuleSet.standard(); s.rules = rules; try saveSet(s) }
}
