import SwiftUI
import AppKit
import UniformTypeIdentifiers
import RatFilterCore

/// Rules manager: rules, profiles and networks, and options.
struct RulesWindow: View {
    @EnvironmentObject var ledger: Ledger

    var body: some View {
        TabView {
            RulesTab().tabItem { Label("Rules", systemImage: "list.bullet.rectangle") }
            ProfilesTab().tabItem { Label("Profiles & Networks", systemImage: "person.2.crop.square.stack") }
            OptionsTab().tabItem { Label("Options", systemImage: "gearshape.2") }
        }
        .frame(minWidth: 820, minHeight: 520)
        .preferredColorScheme(.dark)
    }
}

// MARK: - Rules

struct RulesTab: View {
    @EnvironmentObject var ledger: Ledger
    @State private var filter = Filter.all
    @State private var search = ""
    @State private var editing: Rule?

    enum Filter: String, CaseIterable, Identifiable { case all = "All", unapproved = "Unapproved", deny = "Deny", allow = "Allow"
        var id: String { rawValue } }

    private var rules: RulesModel { ledger.rules }

    private var visible: [Rule] {
        rules.ruleSet.rules.filter { r in
            switch filter {
            case .all: return true
            case .unapproved: return !r.approved
            case .deny: return r.verdict == .deny
            case .allow: return r.verdict == .allow
            }
        }.filter { search.isEmpty || $0.summary.localizedCaseInsensitiveContains(search) }
            .sorted { $0.createdAt > $1.createdAt }
    }

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Picker("", selection: $filter) { ForEach(Filter.allCases) { Text($0.rawValue).tag($0) } }.pickerStyle(.segmented).frame(width: 380)
                TextField("Search rules", text: $search).textFieldStyle(.roundedBorder).frame(maxWidth: 180)
                Spacer()
                Button { editing = Rule(verdict: .allow, profileID: rules.ruleSet.activeProfileID) } label: { Label("New Rule", systemImage: "plus") }
                Button { importRules() } label: { Label("Import…", systemImage: "square.and.arrow.down") }
                Button { exportRules() } label: { Label("Export…", systemImage: "square.and.arrow.up") }
            }.padding(12)

            if rules.unapprovedCount > 0 {
                HStack {
                    Circle().fill(.blue).frame(width: 9, height: 9)
                    Text("\(rules.unapprovedCount) rule\(rules.unapprovedCount == 1 ? "" : "s") waiting for review")
                    Spacer()
                    Button("Approve All") { rules.approveAll() }
                    Button("Reject All", role: .destructive) { rules.rejectAllUnapproved() }
                }
                .padding(.horizontal, 12).padding(.vertical, 8).background(.blue.opacity(0.15))
            }

            List {
                ForEach(visible) { r in RuleRow(rule: r, edit: { editing = r }) }
            }
            .overlay { if visible.isEmpty { Text("No rules").foregroundStyle(.secondary) } }

            if let m = rules.lastMessage { Text(m).font(.caption).foregroundStyle(.secondary).padding(8) }
        }
        .sheet(item: $editing) { rule in RuleEditor(rule: rule) { rules.upsert($0); editing = nil } cancel: { editing = nil } }
    }

    private func importRules() {
        let p = NSOpenPanel(); p.allowedContentTypes = [.json]; p.allowsMultipleSelection = false
        if p.runModal() == .OK, let url = p.url { rules.importRules(from: url) }
    }

    private func exportRules() {
        let p = NSSavePanel(); p.allowedContentTypes = [.json]; p.nameFieldStringValue = "Rat Rules.json"
        if p.runModal() == .OK, let url = p.url { rules.exportRules(to: url) }
    }
}

struct RuleRow: View {
    @EnvironmentObject var ledger: Ledger
    let rule: Rule
    let edit: () -> Void

    var body: some View {
        HStack(spacing: 10) {
            Circle().fill(rule.approved ? .clear : .blue).frame(width: 9, height: 9)
            Image(systemName: rule.verdict == .deny ? "xmark.circle.fill" : "checkmark.circle.fill").foregroundStyle(rule.verdict == .deny ? .red : .green)
            VStack(alignment: .leading, spacing: 1) {
                Text(rule.summary).lineLimit(1)
                Text(detail).font(.caption).foregroundStyle(.secondary)
            }
            Spacer()
            if !rule.approved {
                Button("Approve") { ledger.rules.approve(rule.id) }
                Button("Reject", role: .destructive) { ledger.rules.reject(rule.id) }
            } else {
                Toggle("", isOn: Binding(get: { rule.enabled }, set: { var r = rule; r.enabled = $0; ledger.rules.upsert(r) })).labelsHidden()
                Button { edit() } label: { Image(systemName: "pencil") }.buttonStyle(.borderless)
                Button { ledger.rules.reject(rule.id) } label: { Image(systemName: "trash") }.buttonStyle(.borderless)
            }
        }
        .opacity(rule.enabled ? 1 : 0.5)
    }

    private var detail: String {
        let rs = ledger.rules.ruleSet
        var parts: [String] = []
        parts.append(rule.profileID.flatMap { id in rs.profiles.first { $0.id == id }?.name } ?? "All profiles")
        if let g = rule.groupID.flatMap({ id in rs.groups.first { $0.id == id }?.name }) { parts.append(g) }
        if rule.lifetime != .forever { parts.append("until quit") }
        if let n = rule.note { parts.append(n) }
        return parts.joined(separator: " · ")
    }
}

/// Edit a rule's granularity: process / team ID / domain / host / address / port / protocol.
struct RuleEditor: View {
    @EnvironmentObject var ledger: Ledger
    @State var rule: Rule
    let save: (Rule) -> Void
    let cancel: () -> Void

    enum ProcessScope: String, CaseIterable, Identifiable { case any = "Any process", app = "Application", team = "Team ID", signing = "Signing ID"
        var id: String { rawValue } }
    enum RemoteScope: String, CaseIterable, Identifiable { case any = "Any server", domain = "Domain (and subdomains)", host = "Exact host", address = "IP address"
        var id: String { rawValue } }

    @State private var processScope: ProcessScope = .any
    @State private var processValue = ""
    @State private var remoteScope: RemoteScope = .any
    @State private var remoteValue = ""
    @State private var portText = ""
    @State private var protocolChoice = 0   // 0 any, 1 TCP, 2 UDP

    var body: some View {
        Form {
            Picker("Action", selection: $rule.verdict) { Text("Allow").tag(Verdict.allow); Text("Deny").tag(Verdict.deny) }.pickerStyle(.segmented)
            Section("Process") {
                Picker("Match", selection: $processScope) { ForEach(ProcessScope.allCases) { Text($0.rawValue).tag($0) } }
                if processScope != .any { TextField(processScope == .app ? "Path, e.g. /Applications/Safari.app" : "Value", text: $processValue) }
            }
            Section("Server") {
                Picker("Match", selection: $remoteScope) { ForEach(RemoteScope.allCases) { Text($0.rawValue).tag($0) } }
                if remoteScope != .any { TextField("Value", text: $remoteValue) }
                TextField("Port or range (e.g. 443 or 8000-8100)", text: $portText)
                Picker("Protocol", selection: $protocolChoice) { Text("Any").tag(0); Text("TCP").tag(1); Text("UDP").tag(2) }.pickerStyle(.segmented)
            }
            Section("Where it applies") {
                Picker("Profile", selection: $rule.profileID) {
                    Text("All profiles").tag(UUID?.none)
                    ForEach(ledger.rules.ruleSet.profiles) { Text($0.name).tag(UUID?.some($0.id)) }
                }
                Picker("Group", selection: $rule.groupID) {
                    Text("None").tag(UUID?.none)
                    ForEach(ledger.rules.ruleSet.groups) { Text($0.name).tag(UUID?.some($0.id)) }
                }
                Toggle("Enabled", isOn: $rule.enabled)
            }
            Text(preview.summary).font(.callout).foregroundStyle(.secondary)
            HStack { Spacer(); Button("Cancel", action: cancel).keyboardShortcut(.cancelAction); Button("Save") { save(preview) }.keyboardShortcut(.defaultAction).disabled(!valid) }
        }
        .formStyle(.grouped).frame(width: 460, height: 560)
        .onAppear(perform: load)
    }

    private var parsedPorts: ClosedRange<Int>?? {
        let t = portText.trimmingCharacters(in: .whitespaces)
        if t.isEmpty { return .some(nil) }
        let parts = t.split(separator: "-").map { Int($0.trimmingCharacters(in: .whitespaces)) }
        if parts.count == 1, let p = parts[0], (1...65535).contains(p) { return .some(p...p) }
        if parts.count == 2, let a = parts[0], let b = parts[1], a <= b, (1...65535).contains(a), (1...65535).contains(b) { return .some(a...b) }
        return nil
    }

    private var valid: Bool {
        parsedPorts != nil && (processScope == .any || !processValue.isEmpty) && (remoteScope == .any || !remoteValue.isEmpty)
    }

    private var preview: Rule {
        var r = rule
        r.processPath = nil; r.teamID = nil; r.signingID = nil
        switch processScope { case .any: break; case .app: r.processPath = processValue; case .team: r.teamID = processValue; case .signing: r.signingID = processValue }
        r.remoteDomain = nil; r.remoteHost = nil; r.remoteAddress = nil
        switch remoteScope { case .any: break; case .domain: r.remoteDomain = remoteValue; case .host: r.remoteHost = remoteValue; case .address: r.remoteAddress = remoteValue }
        r.ports = parsedPorts ?? nil
        r.proto = protocolChoice == 1 ? .tcp : protocolChoice == 2 ? .udp : nil
        return r
    }

    private func load() {
        if let p = rule.processPath { processScope = .app; processValue = p }
        else if let t = rule.teamID { processScope = .team; processValue = t }
        else if let s = rule.signingID { processScope = .signing; processValue = s }
        if let d = rule.remoteDomain { remoteScope = .domain; remoteValue = d }
        else if let h = rule.remoteHost { remoteScope = .host; remoteValue = h }
        else if let a = rule.remoteAddress { remoteScope = .address; remoteValue = a }
        if let p = rule.ports { portText = p.lowerBound == p.upperBound ? "\(p.lowerBound)" : "\(p.lowerBound)-\(p.upperBound)" }
        protocolChoice = rule.proto == .tcp ? 1 : rule.proto == .udp ? 2 : 0
    }
}

// MARK: - Profiles & networks

struct ProfilesTab: View {
    @EnvironmentObject var ledger: Ledger
    @State private var newName = ""
    @State private var newGroup = ""

    var body: some View {
        let rules = ledger.rules
        HSplitView {
            VStack(alignment: .leading, spacing: 8) {
                Text("Profiles").font(.headline)
                List {
                    ForEach(rules.ruleSet.profiles) { p in
                        HStack {
                            Image(systemName: p.symbol)
                            Text(p.name)
                            Spacer()
                            if p.id == rules.ruleSet.activeProfileID { Text("Active").font(.caption).foregroundStyle(.green) }
                            else { Button("Activate") { rules.activate(p.id) }.buttonStyle(.borderless) }
                            Button { rules.removeProfile(p.id) } label: { Image(systemName: "trash") }.buttonStyle(.borderless)
                                .disabled(rules.ruleSet.profiles.count < 2)
                        }
                    }
                }
                HStack { TextField("New profile", text: $newName).textFieldStyle(.roundedBorder); Button("Add") { rules.addProfile(named: newName); newName = "" } }
                Divider()
                Text("Rule Groups").font(.headline)
                List {
                    ForEach(rules.ruleSet.groups) { g in
                        HStack {
                            Toggle(g.name, isOn: Binding(get: { g.enabled }, set: { v in
                                if let i = rules.ruleSet.groups.firstIndex(where: { $0.id == g.id }) { rules.ruleSet.groups[i].enabled = v } })).toggleStyle(.switch)
                            Spacer()
                            Button { rules.ruleSet.groups.removeAll { $0.id == g.id } } label: { Image(systemName: "trash") }.buttonStyle(.borderless)
                        }
                    }
                }
                HStack {
                    TextField("New group", text: $newGroup).textFieldStyle(.roundedBorder)
                    Button("Add") { if !newGroup.isEmpty { rules.ruleSet.groups.append(RuleGroup(name: newGroup)); newGroup = "" } }
                }
            }.padding(14).frame(minWidth: 360)

            VStack(alignment: .leading, spacing: 10) {
                Text("Automatic Profile Switching").font(.headline)
                Toggle("Enable automatic profile switching", isOn: Binding(get: { rules.ruleSet.automaticProfileSwitching }, set: { rules.ruleSet.automaticProfileSwitching = $0 }))
                Text("When joining a known network, its profile is activated automatically.").font(.callout).foregroundStyle(.secondary)
                if let net = rules.currentNetwork {
                    GroupBox("Current network: \(net.name)") {
                        Menu("Use a profile on this network…") {
                            ForEach(rules.ruleSet.profiles) { p in Button(p.name) { rules.rememberCurrentNetwork(profile: p.id) } }
                        }
                    }
                } else { Text("No network detected.").foregroundStyle(.secondary) }
                Text("Known networks").font(.subheadline.weight(.semibold))
                List {
                    ForEach(rules.ruleSet.triggers) { t in
                        HStack {
                            Image(systemName: "wifi")
                            VStack(alignment: .leading) {
                                Text(t.name)
                                Text(rules.ruleSet.profiles.first { $0.id == t.profileID }?.name ?? "?").font(.caption).foregroundStyle(.secondary)
                            }
                            Spacer()
                            Button { rules.ruleSet.triggers.removeAll { $0.id == t.id } } label: { Image(systemName: "trash") }.buttonStyle(.borderless)
                        }
                    }
                }
                Text("Wi-Fi names need Location access in macOS; without it, networks are recognized by their gateway address.")
                    .font(.caption).foregroundStyle(.secondary)
            }.padding(14).frame(minWidth: 340)
        }
    }
}

// MARK: - Options

struct OptionsTab: View {
    @EnvironmentObject var ledger: Ledger

    var body: some View {
        let rules = ledger.rules, enf = ledger.enforcer
        Form {
            Section("Connection alerts") {
                Picker("Mode", selection: Binding(get: { rules.silentMode }, set: { rules.silentMode = $0 })) {
                    ForEach(SilentMode.allCases) { Text($0.rawValue).tag($0) }
                }
                Toggle("Mark new rules as unapproved", isOn: Binding(get: { rules.ruleSet.markNewRulesAsUnapproved }, set: { rules.ruleSet.markNewRulesAsUnapproved = $0 }))
                Text("New rules from alerts and the process list are flagged with a blue dot until you approve them. Imported rules always start unapproved and disabled.")
                    .font(.caption).foregroundStyle(.secondary)
            }
            Section("Firewall enforcement") {
                if enf.helperInstalled {
                    Toggle("Auto-apply firewall rules", isOn: Binding(get: { enf.autoApply }, set: { enf.autoApply = $0; ledger.refreshBlocklist() }))
                    Label(ledger.systemWide ? "Seeing all processes system-wide" : "Waiting for the first system snapshot…", systemImage: "eye")
                    Button("Remove Helper…", role: .destructive) { enf.removeHelper() }.disabled(enf.busy)
                } else {
                    Text("Deny blocks server addresses with the macOS packet filter. Without the helper you click “Apply blocking” each time and see only your own processes.")
                        .font(.callout).foregroundStyle(.secondary)
                    Button(enf.busy ? "Installing…" : "Install Background Helper…") { enf.installHelper() }.disabled(enf.busy)
                    Text("Installs two root LaunchDaemons after an administrator-password prompt: one applies the blocklist the moment it changes, the other lists every process's connections. “Remove Helper” uninstalls both and clears the firewall table.")
                        .font(.caption).foregroundStyle(.secondary)
                }
                if let err = enf.lastError { Text(err).font(.caption).foregroundStyle(.red) }
                Text("A blocked address is blocked for every app on this Mac: Rat cannot block per process without Apple's Network Extension entitlement.")
                    .font(.caption).foregroundStyle(.secondary)
            }
            Section("About") {
                Text("Server locations come from the DB-IP.com Lite database (CC BY 4.0) bundled with Rat. Lookups happen on this Mac; nothing is sent anywhere.")
                    .font(.caption).foregroundStyle(.secondary)
            }
        }.formStyle(.grouped)
    }
}
