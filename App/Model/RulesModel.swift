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
        Self.repair(&set)
        ruleSet = set
        engine = RuleEngine(ruleSet: set)
    }

    /// Fixes rules written by earlier versions: an IP address saved as a "domain" (it could never match), and
    /// versioned executables ("…/claude/versions/2.1.308") that should refer to the tool, not one version.
    static func repair(_ set: inout RuleSet) {
        for i in set.rules.indices {
            if let d = set.rules[i].remoteDomain, isIPLiteral(d) {
                set.rules[i].remoteAddress = d
                set.rules[i].remoteDomain = nil
            }
            if let p = set.rules[i].processPath, !p.contains(".app") || p.contains(".AppBundle/") {
                let resolved = AppIdentity.resolve(processPath: p).id
                if resolved != p && resolved != "macOS" { set.rules[i].processPath = resolved }
            }
        }
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
        guard ruleSet.automaticProfileSwitching, let net else { return }
        if let target = engine.profile(forNetwork: net.signature) {
            switchAutomatically(to: target, network: net)
            return
        }
        switch ruleSet.unknownNetworkAction {
        case .ask: askForProfile(network: net)
        case .activate(let id): if ruleSet.profiles.contains(where: { $0.id == id }) { switchAutomatically(to: id, network: net) }
        case .doNothing, .deactivate: break
        }
    }

    private func switchAutomatically(to id: UUID, network: NetworkWatcher.Network) {
        guard ruleSet.activeProfileID != id else { return }
        activate(id)
        if AppSettings.shared.notifyProfileSwitch, let name = activeProfile?.name {
            Notifier.post(title: "Profile switched to “\(name)”", body: "Joined \(network.name)")
        }
    }

    /// "When joining an unknown network: Ask".
    private func askForProfile(network: NetworkWatcher.Network) {
        let alert = NSAlert()
        alert.messageText = "Joined “\(network.name)”"
        alert.informativeText = "Which profile should be active on this network? Rat will switch to it automatically next time."
        let popup = NSPopUpButton(frame: NSRect(x: 0, y: 0, width: 240, height: 26))
        for p in ruleSet.profiles { popup.addItem(withTitle: p.name) }
        popup.selectItem(withTitle: activeProfile?.name ?? "")
        alert.accessoryView = popup
        alert.addButton(withTitle: "Use Profile")
        alert.addButton(withTitle: "Not Now")
        NSApp.activate(ignoringOtherApps: true)
        guard alert.runModal() == .alertFirstButtonReturn, popup.indexOfSelectedItem >= 0, popup.indexOfSelectedItem < ruleSet.profiles.count else { return }
        let target = ruleSet.profiles[popup.indexOfSelectedItem].id
        rememberCurrentNetwork(profile: target)
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

    // The ✗/✓ of a row: one rule per row in the active profile, replaced when the button changes. Which of them
    // decides is `RuleEngine.decide`: the narrowest level first, over the app's rules from alerts.

    private func activeHere(_ r: Rule) -> Bool { r.profileID == nil || r.profileID == ruleSet.activeProfileID }

    private func policy(where match: (Rule) -> Bool) -> Policy? {
        ruleSet.rules.first { match($0) && $0.enabled && activeHere($0) }.map { $0.verdict == .deny ? .deny : .allow }
    }

    private func setPolicy(_ p: Policy?, where match: (Rule) -> Bool, make: (Verdict) -> Rule) {
        ruleSet.rules.removeAll { match($0) && activeHere($0) }
        guard let p else { return }
        var r = make(p == .allow ? .allow : .deny)
        r.approved = !ruleSet.markNewRulesAsUnapproved
        r.profileID = ruleSet.activeProfileID
        r.note = "From the process list"
        ruleSet.rules.append(r)
    }

    private func isWholeAppRule(_ r: Rule, _ appID: String) -> Bool { r.processPath == appID && r.isWholeApp }

    func policy(for appID: String) -> Policy? { policy { isWholeAppRule($0, appID) } }

    func setPolicy(_ p: Policy?, for appID: String) {
        setPolicy(p, where: { isWholeAppRule($0, appID) }) { Rule(verdict: $0, processPath: appID, listLevel: .app) }
    }

    /// One process of an app (`executable`: the path of a helper, an updater, or the system service working for it).
    private func isProcessRule(_ r: Rule, _ appID: String, _ executable: String) -> Bool {
        r.listLevel == .process && r.processPath == appID && r.executable.map { ProgramPath.same($0, executable) } == true
    }

    func processPolicy(app appID: String, executable: String) -> Policy? { policy { isProcessRule($0, appID, executable) } }

    func setProcessPolicy(_ p: Policy?, app appID: String, executable: String) {
        setPolicy(p, where: { isProcessRule($0, appID, executable) }) { Rule(verdict: $0, processPath: appID, executable: executable, listLevel: .process) }
    }

    /// One connection of one process: the server by name when it has one (else its address), its port and protocol.
    struct Endpoint: Hashable {
        var host: String?
        var address: String
        var port: Int
        var proto: Connection.Proto
        /// The server's country, for the rules about a connection (never part of the ✗/✓'s own rule).
        var country: String? = nil
        /// The name a rule keeps: none for a raw address, or for a name that is an address.
        var name: String? { host.flatMap { $0 == address || isIPLiteral($0) ? nil : $0 } }
    }

    private func isConnectionRule(_ r: Rule, _ appID: String, _ executable: String, _ e: Endpoint) -> Bool {
        r.listLevel == .connection && r.processPath == appID && r.executable.map { ProgramPath.same($0, executable) } == true
            && r.ports == e.port...e.port && r.proto == e.proto
            && (e.name.map { r.remoteHost == $0 && r.remoteAddress == nil } ?? (r.remoteAddress == e.address && r.remoteHost == nil))
    }

    func connectionPolicy(app appID: String, executable: String, _ e: Endpoint) -> Policy? { policy { isConnectionRule($0, appID, executable, e) } }

    func setConnectionPolicy(_ p: Policy?, app appID: String, executable: String, _ e: Endpoint) {
        setPolicy(p, where: { isConnectionRule($0, appID, executable, e) }) {
            Rule(verdict: $0, processPath: appID, executable: executable, listLevel: .connection,
                 remoteHost: e.name, remoteAddress: e.name == nil ? e.address : nil, ports: e.port...e.port, proto: e.proto)
        }
    }

    /// Whether a ✓ on one of the app's processes or connections makes an exception to the app's ✗: then the app is
    /// not blocked as a whole, only the sockets the rules deny.
    func hasNarrowerAllow(app appID: String) -> Bool {
        ruleSet.rules.contains { $0.processPath == appID && $0.enabled && activeHere($0) && $0.verdict == .allow
            && ($0.listLevel == .process || $0.listLevel == .connection) }
    }

    func rules(for appID: String) -> [Rule] {
        ruleSet.rules.filter { $0.processPath == appID }
    }

    // MARK: only through a VPN (the inspector's switch)

    /// The "Only through a VPN" rule of an app, or of one of its processes: a deny for every connection that leaves
    /// outside a VPN tunnel (`Rule.requireVPN`), and for nothing else.
    private func isVPNOnlyRule(_ r: Rule, _ t: Target) -> Bool {
        r.requireVPN && r.verdict == .deny && r.processPath == t.app && r.signingID == nil && r.teamID == nil
            && r.remoteDomain == nil && r.remoteHost == nil && r.remoteAddress == nil && r.ports == nil && r.proto == nil && r.country == nil
            && (t.executable.map { exe in r.executable.map { ProgramPath.same($0, exe) } == true } ?? (r.executable == nil))
    }

    /// Whether an app or process row (not a connection) has its own "Only through a VPN".
    func vpnOnly(_ t: Target) -> Bool {
        t.endpoint == nil && ruleSet.rules.contains { isVPNOnlyRule($0, t) && $0.enabled && activeHere($0) }
    }

    /// A process follows its app's "Only through a VPN".
    func vpnOnlyInherited(_ t: Target) -> Bool { t.level == .process && vpnOnly(Target(app: t.app)) }

    /// The VPN country a row's "Only through a VPN" names (`Rule.vpnCountry`): its own, else (a process) its app's.
    func vpnCountry(_ t: Target) -> String? {
        let own = ruleSet.rules.first { isVPNOnlyRule($0, t) && $0.enabled && activeHere($0) }
        return own.map(\.vpnCountry) ?? (t.level == .process ? vpnCountry(Target(app: t.app)) : nil)
    }

    /// Names the VPN's country on the row's own "Only through a VPN" (nil for any VPN); nothing without one.
    func setVPNCountry(_ country: String?, for t: Target) {
        guard t.endpoint == nil, let i = ruleSet.rules.firstIndex(where: { isVPNOnlyRule($0, t) && $0.enabled && activeHere($0) }) else { return }
        ruleSet.rules[i].vpnCountry = Rule.countryCode(country)
    }

    /// `country` names the VPN's country (`Rule.vpnCountry`) for a rule switched on.
    func setVPNOnly(_ on: Bool, for t: Target, country: String? = nil) {
        guard t.endpoint == nil else { return }
        ruleSet.rules.removeAll { isVPNOnlyRule($0, t) && activeHere($0) }
        guard on else { return }
        var r = Rule(verdict: .deny, processPath: t.app, executable: t.executable, requireVPN: true, vpnCountry: country)
        r.approved = !ruleSet.markNewRulesAsUnapproved
        r.profileID = ruleSet.activeProfileID
        r.note = "Only through a VPN"
        ruleSet.rules.append(r)
    }

    // MARK: rows of the process list (app, process, connection)

    /// One row of the process list as rules see it: an app (its `ruleKey`), one of its processes (`executable`), or
    /// one connection of that process (`endpoint`, which needs the executable).
    struct Target: Hashable {
        var app: String
        var executable: String? = nil
        var endpoint: Endpoint? = nil

        var level: ListLevel { endpoint != nil ? .connection : executable != nil ? .process : .app }
        /// The row one level wider: a connection's process, a process's app.
        var parent: Target? {
            switch level {
            case .connection: Target(app: app, executable: executable)
            case .process: Target(app: app)
            case .app: nil
            }
        }
    }

    /// A row's ✗/✓: its own choice, and the one it follows without one (the nearest wider row's: a connection
    /// follows its process, a process its app), the order `RuleEngine.decide` takes them in.
    struct RowPolicy: Equatable {
        var own: Policy?
        var inherited: Policy?
        var effective: Policy? { own ?? inherited }
    }

    func ownPolicy(_ t: Target) -> Policy? {
        switch (t.executable, t.endpoint) {
        case (let exe?, let e?): connectionPolicy(app: t.app, executable: exe, e)
        case (let exe?, nil): processPolicy(app: t.app, executable: exe)
        case (nil, _): policy(for: t.app)
        }
    }

    func rowPolicy(_ t: Target) -> RowPolicy {
        var inherited: Policy?
        var up = t.parent
        while inherited == nil, let p = up { inherited = ownPolicy(p); up = p.parent }
        return RowPolicy(own: ownPolicy(t), inherited: inherited)
    }

    private static func inside(_ path: String, _ prefix: String) -> Bool { ProgramPath.inside(path, prefix) }

    /// The connection a connection target stands for, as the engine judges it.
    private func connection(_ t: Target, signing: (String?, String?)) -> Connection? {
        guard let exe = t.executable, let e = t.endpoint else { return nil }
        return Connection(process: ProcessIdentity(signingID: signing.0, teamID: signing.1, path: t.app), executable: exe,
                          host: e.name, address: e.address, port: e.port, proto: e.proto, country: e.country)
    }

    /// The rules about a row, disabled ones included: for an app, those naming it or a program inside it; for a
    /// process, those naming its app or itself and no other process; for a connection, every rule that matches it
    /// (rules for any process too), as the engine would see it in the active profile.
    func rules(for t: Target, signing: (String?, String?) = (nil, nil)) -> [Rule] {
        let here = ruleSet.rules.filter(activeHere)
        switch t.level {
        case .app:
            return here.filter { $0.processPath.map { Self.inside($0, t.app) } ?? false }
        case .process:
            let exe = t.executable!
            return here.filter { r in
                guard let p = r.processPath, Self.inside(t.app, p) || Self.inside(exe, p) else { return false }
                return r.executable.map { Self.inside(exe, $0) } ?? true
            }
        case .connection:
            guard let c = connection(t, signing: signing) else { return [] }
            // "Only through a VPN" is listed for every connection it can cut, through the VPN or not.
            return here.filter { var r = $0; r.enabled = true; r.requireVPN = false; return r.matches(c) }
        }
    }

    /// The rule that decides a connection now (nil when none does: silent mode or an alert).
    func decidingRule(for t: Target, signing: (String?, String?) = (nil, nil)) -> Rule? {
        connection(t, signing: signing).flatMap { engine.decide($0).rule }
    }

    /// The Rules window's New Rule for a row: its app, process and server, port and protocol filled in.
    func newRule(for t: Target?) -> Rule {
        var r = Rule(verdict: .allow, profileID: ruleSet.activeProfileID)
        guard let t else { return r }
        r.processPath = t.app
        r.executable = t.executable
        if let e = t.endpoint {
            r.remoteHost = e.name; r.remoteAddress = e.name == nil ? e.address : nil
            r.ports = e.port...e.port; r.proto = e.proto
        }
        return r
    }

    /// Set by the inspector's Manage Rules…: the Rules window opens on this row's rules.
    @Published var focus: Target?
    /// Set by a country's rule button (the inspector, a country group): the Rules window opens its editor on it.
    @Published var draft: Rule?

    /// A rule for the servers in one country, for one app or (with none) any process: a deny to start from, which
    /// the editor can turn into an allow.
    func newCountryRule(_ country: String, app: String?) -> Rule {
        Rule(verdict: .deny, processPath: app, country: country, profileID: ruleSet.activeProfileID)
    }

    // MARK: alert answers

    enum Scope: String, CaseIterable, Identifiable {
        case any = "This App (Any Server)", domain = "Domain", host = "Exact host", port = "Port"
        var id: String { rawValue }
    }

    func addRule(from alert: ConnectionAlert, verdict: Verdict, scope: Scope, lifetime: Lifetime) {
        // "Once" allow needs no rule. "Once" deny is a session rule so the open connection is really cut.
        if lifetime == .once && verdict == .allow { return }
        var r = Rule(verdict: verdict, processPath: alert.appID, approved: !ruleSet.markNewRulesAsUnapproved,
                     lifetime: lifetime == .once ? .untilQuit : lifetime, profileID: ruleSet.activeProfileID, note: "From a connection alert")
        switch scope {
        case .any: break
        case .domain:
            // A raw IP has no domain: scope it to the address instead.
            if !isIPLiteral(alert.host) { r.remoteDomain = registrableDomain(alert.host) } else { r.remoteAddress = alert.address }
        case .host: if !isIPLiteral(alert.host) { r.remoteHost = alert.host } else { r.remoteAddress = alert.address }
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
