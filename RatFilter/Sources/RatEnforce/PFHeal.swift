import Foundation

/// Keeps pf running and Rat's anchor evaluated when another program changes pf behind Rat's back. VPN clients
/// with a kill switch do both: Cloudflare WARP writes the main ruleset straight through /dev/pf (an "overwriting
/// commit" that drops Apple's `anchor "com.apple/*"`, so `com.apple/rat` is no longer evaluated), and a client that
/// stops pf when it disconnects (`pfctl -d`) also cancels every enable reference, Rat's included.
///
/// The repair never takes another program's rules away while pf runs them. Only when pf is off (so they do nothing)
/// is /etc/pf.conf loaded again, as macOS does at startup: turning pf on with a disconnected VPN's kill switch
/// still loaded would cut the Mac off. While pf runs, Apple's anchors are put back next to the other program's
/// anchors, whose rules stay as they are; a main ruleset with rules of its own (not anchors) is left alone unless
/// the user asks for the repair (Settings > Security).
public enum PFHeal {
    public enum Plan: Equatable {
        /// pf runs and evaluates Rat's anchor.
        case none
        /// pf is off and holds only Apple's anchors: turn it on.
        case enable
        /// pf is off with another program's rules loaded, or the main ruleset is empty: load /etc/pf.conf, then
        /// turn pf on.
        case reloadSystemConfig
        /// pf runs but the main ruleset lost Apple's anchors: load this NAT and filter ruleset (`pfctl -N -R`), Apple's
        /// anchors followed by the other program's, so pf's options and the anchors' own rules stay as they are.
        case rehook(String)
        /// Nothing Rat may do on its own; the reason is shown in Settings > Security.
        case blocked(String)
    }

    static let apple = "com.apple/*"
    private static let kinds = ["scrub-anchor", "nat-anchor", "rdr-anchor", "binat-anchor", "dummynet-anchor", "anchor"]

    struct Line: Equatable {
        let kind: String
        let name: String
        let text: String
    }

    /// The anchor points of a main ruleset as `pfctl -s rules` / `-s nat` print them, or nil if it also holds
    /// rules of its own. pfctl's ALTQ notices (stderr is read too) are skipped.
    static func anchorLines(_ output: String) -> [Line]? {
        var out: [Line] = []
        for raw in output.split(whereSeparator: \.isNewline) {
            let text = raw.trimmingCharacters(in: .whitespaces)
            if text.isEmpty || text.hasPrefix("No ALTQ") || text.hasPrefix("ALTQ") { continue }
            guard let space = text.firstIndex(of: " "), kinds.contains(String(text[..<space])) else { return nil }
            let rest = text[text.index(after: space)...]
            guard rest.first == "\"", let close = rest.dropFirst().firstIndex(of: "\"") else { return nil }
            out.append(Line(kind: String(text[..<space]), name: String(rest[rest.index(after: rest.startIndex)..<close]), text: text))
        }
        return out
    }

    /// Whether /etc/pf.conf (comments aside) still hooks Apple's anchors, as macOS ships it.
    public static func systemConfigHooks(_ config: String) -> Bool {
        config.split(whereSeparator: \.isNewline).contains { line in
            let t = line.trimmingCharacters(in: .whitespaces)
            return t.hasPrefix("anchor \"\(apple)\"")
        }
    }

    /// What to do about pf. `rules` and `nat` are the main ruleset (`pfctl -s rules`, `pfctl -s nat`), `config` is
    /// /etc/pf.conf, and `force` is the user's Repair (it may replace another program's own rules while pf runs).
    public static func plan(enabled: Bool, rules: String, nat: String, config: String, anchor: String, force: Bool = false) -> Plan {
        let filterLines = anchorLines(rules), natLines = anchorLines(nat)
        let ownRules = filterLines == nil || natLines == nil
        let lines = (filterLines ?? []) + (natLines ?? [])
        let hooked = PFStates.hooksAnchor(rules, anchor: anchor)
        let foreign = lines.filter { $0.name != apple }
        let configHooks = systemConfigHooks(config)
        let configChanged = "/etc/pf.conf was changed and no longer loads the com.apple anchors (anchor \"com.apple/*\"), so Rat's rules are not evaluated. Rat does not edit it; restore that line."
        if enabled {
            if hooked { return .none }
            if !ownRules { return .rehook(rehookRuleset(foreign)) }
            if force { return configHooks ? .reloadSystemConfig : .blocked(configChanged) }
            return .blocked("Another program replaced pf's main ruleset with rules of its own, so Rat's rules are not evaluated. Rat does not remove them on its own: turn that program's firewall (kill switch) off, or use Repair Firewall to load macOS's pf configuration again.")
        }
        if hooked, !ownRules, foreign.isEmpty { return .enable }
        return configHooks ? .reloadSystemConfig : .blocked(configChanged)
    }

    /// Apple's anchor points (as in /etc/pf.conf) followed by the other program's, in the order pf requires
    /// (normalization, translation, filtering) and otherwise as they were.
    static func rehookRuleset(_ foreign: [Line]) -> String {
        func theirs(_ kinds: Set<String>) -> [String] { foreign.filter { kinds.contains($0.kind) }.map(\.text) }
        let lines = ["scrub-anchor \"\(apple)\""] + theirs(["scrub-anchor"])
            + ["nat-anchor \"\(apple)\"", "rdr-anchor \"\(apple)\""] + theirs(["nat-anchor", "rdr-anchor", "binat-anchor"])
            + ["anchor \"\(apple)\""] + theirs(["anchor"])
        return lines.joined(separator: "\n") + "\n"
    }
}
