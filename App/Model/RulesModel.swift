import SwiftUI
import AppKit
import RatFilterCore
import os

private let logger = Logger(subsystem: "com.imanmontajabi.Rat", category: "rules")

enum Policy: String { case allow, deny }

enum SilentMode: String, CaseIterable, Identifiable {
    case off = "Alert Mode", allow = "Silent Mode: Allow", deny = "Silent Mode: Deny"
    var id: String { rawValue }
}

/// The rule engine, its persistence and everything the Rules window edits.
@MainActor
final class RulesModel: ObservableObject {
    @Published var ruleSet: RuleSet { didSet { engine.ruleSet = ruleSet; scheduleSave() } }
    @Published private(set) var currentNetwork: NetworkWatcher.Network?
    @Published var lastMessage: String?

    let engine: RuleEngine
    private let store: RuleStore
    private var saveTask: Task<Void, Never>?

    init(directory: URL) {
        store = RuleStore(url: directory.appendingPathComponent("rules.json"))
        var set = (try? store.loadSet()) ?? RuleSet.standard()
        if !set.profiles.contains(where: { $0.id == set.activeProfileID }), let first = set.profiles.first { set.activeProfileID = first.id }
        ruleSet = set
        engine = RuleEngine(ruleSet: set)
    }

    // MARK: profiles

    var activeProfile: Profile? { ruleSet.profiles.first { $0.id == ruleSet.activeProfileID } }

    func activate(_ id: UUID) {
        guard ruleSet.activeProfileID != id else { return }
        ruleSet.activeProfileID = id
        logger.notice("profile switched")
    }

    func addProfile(named name: String) {
        let n = name.trimmingCharacters(in: .whitespaces)
        guard !n.isEmpty else { return }
        ruleSet.profiles.append(Profile(name: n))
    }

    func removeProfile(_ id: UUID) {
        guard ruleSet.profiles.count > 1 else { return }
        ruleSet.profiles.removeAll { $0.id == id }
        ruleSet.triggers.removeAll { $0.profileID == id }
        ruleSet.rules.removeAll { $0.profileID == id }
        if ruleSet.activeProfileID == id, let first = ruleSet.profiles.first { ruleSet.activeProfileID = first.id }
    }

    /// Polls the network; with automatic switching on, a known network selects its profile.
    func refreshNetwork() { applyNetwork(NetworkWatcher.current()) }

    func applyNetwork(_ net: NetworkWatcher.Network?) {
        guard net != currentNetwork else { return }
        currentNetwork = net
        guard ruleSet.automaticProfileSwitching, let net, let target = engine.profile(forNetwork: net.signature) else { return }
        activate(target)
    }

    func rememberCurrentNetwork(profile: UUID) {
        guard let net = currentNetwork else { return }
        ruleSet.triggers.removeAll { $0.signature == net.signature }
        ruleSet.triggers.append(NetworkTrigger(signature: net.signature, name: net.name, profileID: profile))
    }

    // MARK: silent mode

    var silentMode: SilentMode {
        get { switch ruleSet.silentVerdict { case .allow?: return .allow; case .deny?: return .deny; default: return .off } }
        set { ruleSet.silentVerdict = newValue == .allow ? .allow : newValue == .deny ? .deny : nil }
    }

    // MARK: per-app policy (the allow/deny buttons in the process list)

    private func isWholeAppRule(_ r: Rule, _ appID: String) -> Bool {
        r.processPath == appID && r.remoteDomain == nil && r.remoteHost == nil && r.remoteAddress == nil && r.ports == nil
            && r.proto == nil && r.signingID == nil && r.teamID == nil
    }

    func policy(for appID: String) -> Policy? {
        let rule = ruleSet.rules.first {
            isWholeAppRule($0, appID) && $0.enabled && ($0.profileID == nil || $0.profileID == ruleSet.activeProfileID)
        }
        return rule.map { $0.verdict == .deny ? .deny : .allow }
    }

    func setPolicy(_ p: Policy?, for appID: String) {
        ruleSet.rules.removeAll { isWholeAppRule($0, appID) && ($0.profileID == nil || $0.profileID == ruleSet.activeProfileID) }
        guard let p else { return }
        ruleSet.rules.append(Rule(verdict: p == .allow ? .allow : .deny, processPath: appID, approved: !ruleSet.markNewRulesAsUnapproved,
                                  profileID: ruleSet.activeProfileID, note: "From the process list"))
    }

    func rules(for appID: String) -> [Rule] {
        ruleSet.rules.filter { $0.processPath == appID }
    }

    // MARK: alert answers

    enum Scope: String, CaseIterable, Identifiable {
        case any = "Any connection", domain = "Domain", host = "Exact host", port = "Port"
        var id: String { rawValue }
    }

    func addRule(from alert: ConnectionAlert, verdict: Verdict, scope: Scope, lifetime: Lifetime) {
        // "Once" allow needs no rule. "Once" deny is a session rule so the open connection is really cut.
        if lifetime == .once && verdict == .allow { return }
        var r = Rule(verdict: verdict, processPath: alert.appID, approved: !ruleSet.markNewRulesAsUnapproved,
                     lifetime: lifetime == .once ? .untilQuit : lifetime, profileID: ruleSet.activeProfileID, note: "From a connection alert")
        switch scope {
        case .any: break
        case .domain: r.remoteDomain = registrableDomain(alert.host)
        case .host: if alert.host.contains(where: \.isLetter) { r.remoteHost = alert.host } else { r.remoteAddress = alert.address }
        case .port: r.ports = alert.port...alert.port; r.proto = alert.proto == "UDP" ? .udp : .tcp
        }
        if lifetime == .once { r.remoteAddress = alert.address; r.ports = alert.port...alert.port }
        ruleSet.rules.append(r)
    }

    // MARK: rule manager

    var unapprovedCount: Int { ruleSet.rules.filter { !$0.approved }.count }

    func approve(_ id: UUID) {
        guard let i = ruleSet.rules.firstIndex(where: { $0.id == id }) else { return }
        ruleSet.rules[i].approved = true; ruleSet.rules[i].enabled = true
    }

    func approveAll() {
        for i in ruleSet.rules.indices where !ruleSet.rules[i].approved { ruleSet.rules[i].approved = true; ruleSet.rules[i].enabled = true }
    }

    func reject(_ id: UUID) { ruleSet.rules.removeAll { $0.id == id } }
    func rejectAllUnapproved() { ruleSet.rules.removeAll { !$0.approved } }

    func upsert(_ rule: Rule) {
        if let i = ruleSet.rules.firstIndex(where: { $0.id == rule.id }) { ruleSet.rules[i] = rule } else { ruleSet.rules.append(rule) }
    }

    func exportRules(to url: URL) {
        do {
            try engine.exportRules().encoded().write(to: url, options: .atomic)
            lastMessage = "Exported \(engine.exportRules().rules.count) rules."
        } catch { lastMessage = "Export failed: \(error.localizedDescription)" }
    }

    func importRules(from url: URL) {
        do {
            let export = try RuleExport.decode(Data(contentsOf: url))
            let before = ruleSet.rules.count
            engine.ruleSet = ruleSet
            let added = engine.importRules(export, markUnapproved: true)
            ruleSet = engine.ruleSet
            lastMessage = "Imported \(added) rules (\(export.rules.count - added) already present). Review and approve them to activate."
            _ = before
        } catch { lastMessage = "Import failed: \(error.localizedDescription)" }
    }

    // MARK: persistence

    func purgeSessionRules() {
        ruleSet.rules.removeAll { $0.lifetime != .forever }
    }

    func saveNow() {
        saveTask?.cancel()
        do { try store.saveSet(ruleSet) } catch { logger.error("rules save failed: \(error.localizedDescription, privacy: .public)") }
    }

    private func scheduleSave() {
        saveTask?.cancel()
        saveTask = Task { [weak self] in
            try? await Task.sleep(for: .milliseconds(400))
            if !Task.isCancelled { self?.saveNow() }
        }
    }
}
