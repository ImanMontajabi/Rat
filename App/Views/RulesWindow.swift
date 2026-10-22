import SwiftUI
import AppKit
import UniformTypeIdentifiers
import RatFilterCore

/// Rules manager. Layout follows Little Snitch's Rules window: a sidebar of rule sets (rules, profiles,
/// rule groups, networks, maintenance) and a rules table with Active / Process / Description / Status columns.
struct RulesWindow: View {
    @EnvironmentObject var ledger: Ledger
    @State private var category: Category = .all
    @State private var newProfile = ""
    @State private var addingProfile = false
    @State private var newGroup = ""
    @State private var addingGroup = false

    enum Category: Hashable {
        case all, unapproved, invalid
        case profile(UUID)
        case group(UUID)
        case networks
    }

    var body: some View {
        let rules = ledger.rules
        NavigationSplitView {
            List(selection: $category) {
                Section("Rules") {
                    Label("All Rules", systemImage: "list.bullet").badge(rules.ruleSet.rules.count).tag(Category.all)
                    Label("Unapproved", systemImage: "circle.fill").foregroundStyle(.primary).badge(rules.unapprovedCount).tag(Category.unapproved)
                }
                Section("Profiles") {
                    ForEach(rules.ruleSet.profiles) { p in
                        HStack {
                            Image(systemName: p.symbol)
                            Text(p.name)
                            Spacer()
                            if p.id == rules.ruleSet.activeProfileID { Image(systemName: "checkmark.circle.fill").foregroundStyle(.green) }
                        }
                        .tag(Category.profile(p.id))
                        .contextMenu {
                            Button("Activate Profile") { rules.activate(p.id) }
                            Button("Delete Profile", role: .destructive) { rules.removeProfile(p.id) }.disabled(rules.ruleSet.profiles.count < 2)
                        }
                    }
                    Button { addingProfile = true } label: { Label("New Profile…", systemImage: "plus") }.buttonStyle(.plain).foregroundStyle(.secondary)
                }
                Section("Rule Groups") {
                    ForEach(rules.ruleSet.groups) { g in
                        HStack {
                            Image(systemName: "folder")
                            Text(g.name)
                            Spacer()
                            Toggle("", isOn: Binding(get: { g.enabled }, set: { v in
                                if let i = rules.ruleSet.groups.firstIndex(where: { $0.id == g.id }) { rules.ruleSet.groups[i].enabled = v } })).labelsHidden().toggleStyle(.switch).controlSize(.mini)
                        }
                        .tag(Category.group(g.id))
                        .contextMenu {
                            Button("Delete Rule Group", role: .destructive) {
                                rules.ruleSet.groups.removeAll { $0.id == g.id }
                                for i in rules.ruleSet.rules.indices where rules.ruleSet.rules[i].groupID == g.id { rules.ruleSet.rules[i].groupID = nil }
                            }
                        }
                    }
                    Button { addingGroup = true } label: { Label("New Rule Group…", systemImage: "plus") }.buttonStyle(.plain).foregroundStyle(.secondary)
                }
                Section("Networks") {
                    Label("Known Networks", systemImage: "wifi").badge(rules.ruleSet.triggers.count).tag(Category.networks)
                }
                Section("Maintenance") {
                    Label("Invalid Rules", systemImage: "exclamationmark.triangle").tag(Category.invalid)
                }
            }
            .listStyle(.sidebar)
            .navigationSplitViewColumnWidth(min: 200, ideal: 230, max: 280)
        } detail: {
            switch category {
            case .networks: NetworksList()
            default: RulesList(category: category)
            }
        }
        .frame(minWidth: 940, minHeight: 540)
        .preferredColorScheme(.dark)
        .alert("New Profile", isPresented: $addingProfile) {
            TextField("Enter a profile name", text: $newProfile)
            Button("Create Profile") { rules.addProfile(named: newProfile); newProfile = "" }
            Button("Cancel", role: .cancel) { newProfile = "" }
        }
        .alert("New Rule Group", isPresented: $addingGroup) {
            TextField("Enter a group name", text: $newGroup)
            Button("Create Group") { if !newGroup.isEmpty { rules.ruleSet.groups.append(RuleGroup(name: newGroup)) }; newGroup = "" }
            Button("Cancel", role: .cancel) { newGroup = "" }
        }
    }
}

struct RulesList: View {
    @EnvironmentObject var ledger: Ledger
    let category: RulesWindow.Category
    @State private var search = ""
    @State private var selection = Set<UUID>()
    @State private var editing: Rule?

    private var rules: RulesModel { ledger.rules }

    private var title: String {
        switch category {
        case .all: return "All Rules"
        case .unapproved: return "Unapproved Rules"
        case .invalid: return "Invalid Rules"
        case .profile(let id): return rules.ruleSet.profiles.first { $0.id == id }?.name ?? "Profile"
        case .group(let id): return rules.ruleSet.groups.first { $0.id == id }?.name ?? "Rule Group"
        case .networks: return ""
        }
    }

    private var subtitle: String {
        switch category {
        case .invalid: return "Possibly ineffective: the applications they refer to were deleted, renamed or moved."
        case .profile: return "Rules that are not assigned to a profile are effective in all profiles."
        case .unapproved: return "Review these rules, then approve or reject them."
        default: return ""
        }
    }

    private var visible: [Rule] {
        rules.ruleSet.rules.filter { r in
            switch category {
            case .all: return true
            case .unapproved: return !r.approved
            case .profile(let id): return r.profileID == id
            case .group(let id): return r.groupID == id
            case .invalid: return r.processPath.map { !FileManager.default.fileExists(atPath: $0) } ?? false
            case .networks: return false
            }
        }
        .filter { search.isEmpty || $0.summary.localizedCaseInsensitiveContains(search) }
        .sorted { $0.createdAt > $1.createdAt }
    }

    var body: some View {
        VStack(spacing: 0) {
            VStack(alignment: .leading, spacing: 2) {
                HStack(alignment: .firstTextBaseline) {
                    Text(title).font(.title2.weight(.semibold))
                    Text("\(visible.count) \(visible.count == 1 ? "rule" : "rules")").foregroundStyle(.secondary)
                    Spacer()
                    if case .profile(let id) = category, id != rules.ruleSet.activeProfileID {
                        Button("Activate") { rules.activate(id) }
                    } else if case .profile = category {
                        Label("Active", systemImage: "checkmark.circle.fill").foregroundStyle(.green)
                    }
                }
                if !subtitle.isEmpty { Text(subtitle).font(.callout).foregroundStyle(.secondary) }
            }.padding(.horizontal, 16).padding(.top, 12).padding(.bottom, 8)

            if rules.unapprovedCount > 0 {
                HStack {
                    Circle().fill(.blue).frame(width: 9, height: 9)
                    Text("\(rules.unapprovedCount) rule\(rules.unapprovedCount == 1 ? "" : "s") waiting for review")
                    Spacer()
                    Button("Approve All") { rules.approveAll() }
                    Button("Reject All", role: .destructive) { rules.rejectAllUnapproved() }
                }
                .padding(.horizontal, 16).padding(.vertical, 8).background(.blue.opacity(0.15))
            }

            Table(visible, selection: $selection) {
                TableColumn("Active") { r in
                    Toggle("", isOn: Binding(get: { r.enabled }, set: { var x = r; x.enabled = $0; rules.upsert(x) })).labelsHidden().toggleStyle(.switch).controlSize(.mini)
                }.width(50)
                TableColumn("Process") { r in
                    HStack(spacing: 6) {
                        Image(systemName: r.verdict == .deny ? "xmark.circle.fill" : "checkmark.circle.fill").foregroundStyle(r.verdict == .deny ? .red : .green)
                        Text(processName(r)).lineLimit(1)
                    }
                }.width(min: 130, ideal: 190, max: 260)
                TableColumn("Description") { r in
                    VStack(alignment: .leading, spacing: 1) {
                        Text(destination(r)).lineLimit(1)
                        Text(membership(r)).font(.caption).foregroundStyle(.secondary).lineLimit(1)
                    }
                }.width(min: 260, ideal: 420)
                TableColumn("Status") { r in
                    HStack(spacing: 6) {
                        if !r.approved { Circle().fill(.blue).frame(width: 8, height: 8); Text("unapproved").font(.caption).fixedSize() }
                        else if r.lifetime != .forever { Text("temporary").font(.caption).foregroundStyle(.secondary) }
                        Spacer()
                        if !r.approved { Button("Approve") { rules.approve(r.id) }.controlSize(.small) }
                    }
                }.width(min: 180, ideal: 200, max: 230)
            }
            .contextMenu(forSelectionType: UUID.self) { ids in
                if !ids.isEmpty {
                    Button("Approve") { ids.forEach(rules.approve) }
                    Button("Delete", role: .destructive) { ids.forEach(rules.reject) }
                }
            } primaryAction: { ids in
                if let id = ids.first { editing = rules.ruleSet.rules.first { $0.id == id } }
            }
            .onChange(of: selection) { _, new in
                // "Approve rules automatically": selecting an unapproved rule approves it.
                guard AppSettings.shared.approveRulesAutomatically else { return }
                for id in new where rules.ruleSet.rules.first(where: { $0.id == id })?.approved == false { rules.approve(id) }
            }
            .overlay { if visible.isEmpty { Text("No \(category == .unapproved ? "unapproved " : "")rules").foregroundStyle(.secondary) } }

            if let m = rules.lastMessage { Text(m).font(.caption).foregroundStyle(.secondary).padding(8) }
        }
        .searchable(text: $search, placement: .toolbar, prompt: "Search rules")
        .toolbar {
            ToolbarItemGroup {
                Button { editing = Rule(verdict: .allow, profileID: rules.ruleSet.activeProfileID) } label: { Label("New Rule", systemImage: "plus") }
                Button(role: .destructive) { selection.forEach(rules.reject); selection = [] } label: { Label("Delete", systemImage: "trash") }.disabled(selection.isEmpty)
                Button { importRules() } label: { Label("Import Rules…", systemImage: "square.and.arrow.down") }
                Button { exportRules() } label: { Label("Export Rules…", systemImage: "square.and.arrow.up") }
            }
        }
        .sheet(item: $editing) { rule in RuleEditor(rule: rule) { rules.upsert($0); editing = nil } cancel: { editing = nil } }
    }

    private func processName(_ r: Rule) -> String {
        if let p = r.processPath { return AppIdentity.resolve(processPath: p.hasSuffix(".app") ? p : p).name }
        return r.signingID ?? r.teamID.map { "Team \($0)" } ?? "Any Process"
    }

    private func destination(_ r: Rule) -> String {
        var what = r.remoteAddress ?? r.remoteHost ?? r.remoteDomain.flatMap { $0 == "*" ? nil : "*.\($0)" } ?? "any server"
        if let ports = r.ports { what += ports.lowerBound == ports.upperBound ? " : \(ports.lowerBound)" : " : \(ports.lowerBound)-\(ports.upperBound)" }
        if let proto = r.proto { what += " (\(proto.rawValue.uppercased()))" }
        return (r.verdict == .deny ? "Deny" : "Allow") + " connections to " + what
    }

    private func membership(_ r: Rule) -> String {
        let rs = rules.ruleSet
        var parts: [String] = []
        parts.append(r.profileID.flatMap { id in rs.profiles.first { $0.id == id }?.name } ?? "All profiles")
        if let g = r.groupID.flatMap({ id in rs.groups.first { $0.id == id }?.name }) { parts.append(g) }
        if let n = r.note { parts.append(n) }
        return parts.joined(separator: " · ")
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

struct NetworksList: View {
    @EnvironmentObject var ledger: Ledger
    var body: some View {
        let rules = ledger.rules
        VStack(alignment: .leading, spacing: 10) {
            Text("Known Networks").font(.title2.weight(.semibold))
            Text("Activate a profile automatically when joining these networks. Automatic profile switching is \(rules.ruleSet.automaticProfileSwitching ? "on" : "off") (Settings > APS).")
                .font(.callout).foregroundStyle(.secondary)
            if let net = rules.currentNetwork {
                HStack {
                    Label("Current: \(net.name)", systemImage: "wifi")
                    Spacer()
                    Menu("Assign to profile…") { ForEach(rules.ruleSet.profiles) { p in Button(p.name) { rules.rememberCurrentNetwork(profile: p.id) } } }.fixedSize()
                }
            }
            List {
                ForEach(rules.ruleSet.triggers) { t in
                    HStack {
                        Image(systemName: "wifi")
                        Text(t.name)
                        Spacer()
                        Text(rules.ruleSet.profiles.first { $0.id == t.profileID }?.name ?? "?").foregroundStyle(.secondary)
                        Button { rules.ruleSet.triggers.removeAll { $0.id == t.id } } label: { Image(systemName: "minus.circle") }.buttonStyle(.borderless)
                    }
                }
            }.overlay { if rules.ruleSet.triggers.isEmpty { Text("No networks assigned to a profile").foregroundStyle(.secondary) } }
        }.padding(16)
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

