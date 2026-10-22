import Foundation

/// Evaluates connections against rules and remembers undecided flows so they can be
/// re-evaluated when rules change (Little Snitch re-applies rules to all live flows
/// on every rule-tree update).
public final class RuleEngine: @unchecked Sendable {
    private let lock = NSLock()
    private var rules: [Rule] = []
    public var defaultVerdict: Verdict

    public init(rules: [Rule] = [], defaultVerdict: Verdict = .ask) {
        self.rules = rules
        self.defaultVerdict = defaultVerdict
    }

    public var allRules: [Rule] { lock.withLock { rules } }

    public func setRules(_ new: [Rule]) { lock.withLock { rules = new } }
    public func add(_ rule: Rule) { lock.withLock { rules.append(rule) } }
    public func remove(id: UUID) { lock.withLock { rules.removeAll { $0.id == id } } }

    public func evaluate(_ c: Connection) -> Verdict {
        let snapshot = lock.withLock { rules }
        let best = snapshot
            .filter { $0.matches(c) }
            .max { a, b in
                if a.specificity != b.specificity { return a.specificity < b.specificity }
                return a.verdict != .deny && b.verdict == .deny   // deny wins ties
            }
        return best?.verdict ?? defaultVerdict
    }
}

/// JSON persistence for the rule set.
public struct RuleStore {
    public let url: URL
    public init(url: URL) { self.url = url }

    public func load() throws -> [Rule] {
        guard FileManager.default.fileExists(atPath: url.path) else { return [] }
        return try JSONDecoder().decode([Rule].self, from: Data(contentsOf: url))
    }

    public func save(_ rules: [Rule]) throws {
        let enc = JSONEncoder()
        enc.outputFormatting = [.prettyPrinted, .sortedKeys]
        try enc.encode(rules).write(to: url, options: .atomic)
    }
}
