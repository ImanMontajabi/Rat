import SwiftUI
import RatFilterCore

/// Settings (⌘,). Tab order, icons and wording follow Little Snitch's Settings window.
/// Tabs that only exist there because of features Rat does not have (DNS encryption, registration) are left out.
struct SettingsView: View {
    @State private var tab = "General"

    var body: some View {
        TabView(selection: $tab) {
            GeneralSettings().tabItem { Label("General", systemImage: "gearshape") }.tag("General")
            MenuBarSettings().tabItem { Label("Control Center", systemImage: "chart.bar.fill") }.tag("Control Center")
            AlertSettings().tabItem { Label("Alert", systemImage: "rectangle.topthird.inset.filled") }.tag("Alert")
            MonitorSettings().tabItem { Label("Monitor", systemImage: "waveform.path.ecg.rectangle") }.tag("Monitor")
            ProfileSwitchingSettings().tabItem { Label("APS", systemImage: "arrow.triangle.2.circlepath.doc.on.clipboard") }.tag("APS")
            SecuritySettings().tabItem { Label("Security", systemImage: "lock") }.tag("Security")
            NotificationSettings().tabItem { Label("Notifications", systemImage: "bell.badge") }.tag("Notifications")
            UpdateSettings().tabItem { Label("Update", systemImage: "arrow.down.circle") }.tag("Update")
            AdvancedSettings().tabItem { Label("Advanced", systemImage: "gearshape.2") }.tag("Advanced")
        }
        #if DEBUG
        .onAppear { if let t = ProcessInfo.processInfo.environment["RAT_SETTINGS_TAB"] { tab = t } }
        #endif
        .frame(width: 640)
        .preferredColorScheme(.dark)
    }
}

// MARK: - building blocks

/// Checkbox with an explanatory line underneath, as in the reference screenshots.
struct SettingToggle: View {
    let title: String
    var detail: String?
    @Binding var isOn: Bool
    var body: some View {
        VStack(alignment: .leading, spacing: 3) {
            Toggle(isOn: $isOn) { Text(title).font(.system(size: 14)) }.toggleStyle(.checkbox)
            if let detail { Text(detail).font(.callout).foregroundStyle(.secondary).padding(.leading, 22).fixedSize(horizontal: false, vertical: true) }
        }
    }
}

struct SettingsPane<Content: View>: View {
    @ViewBuilder let content: Content
    var body: some View {
        VStack(alignment: .leading, spacing: 18) { content }
            .padding(.horizontal, 44).padding(.vertical, 26)
            .frame(maxWidth: .infinity, alignment: .leading)
    }
}

// MARK: - General

struct GeneralSettings: View {
    @EnvironmentObject var ledger: Ledger
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        let rules = ledger.rules
        SettingsPane {
            HStack(alignment: .firstTextBaseline, spacing: 10) {
                Text("Network Filter:").frame(width: 130, alignment: .trailing)
                Label("On", systemImage: "circle.fill").foregroundStyle(.green).labelStyle(.titleAndIcon)
            }
            Text("Connections are checked against the set of specified rules. Rat sees them as they start, so unknown ones are answered after the fact.")
                .font(.callout).foregroundStyle(.secondary).padding(.leading, 140)
            HStack(alignment: .firstTextBaseline, spacing: 10) {
                Text("Operation Mode:").frame(width: 130, alignment: .trailing)
                Picker("", selection: Binding(get: { rules.silentMode }, set: { rules.silentMode = $0 })) {
                    Text("Alert").tag(SilentMode.off)
                    Text("Silent Allow").tag(SilentMode.allow)
                    Text("Silent Deny").tag(SilentMode.deny)
                }.labelsHidden().frame(width: 180)
            }
            Text("When Silent Mode is active, no connection alert will be shown for connection attempts. Instead, the connection will be allowed or denied as specified.")
                .font(.callout).foregroundStyle(.secondary).padding(.leading, 140)
            HStack(alignment: .firstTextBaseline, spacing: 10) {
                Text("Active Profile:").frame(width: 130, alignment: .trailing)
                Picker("", selection: Binding(get: { rules.ruleSet.activeProfileID }, set: { rules.activate($0) })) {
                    ForEach(rules.ruleSet.profiles) { Text($0.name).tag($0.id) }
                }.labelsHidden().frame(width: 180)
                Button("Edit Profiles…") { openWindow(id: "rules") }
            }
        }
    }
}

// MARK: - Control Center (menu bar)

struct MenuBarSettings: View {
    @ObservedObject private var s = AppSettings.shared
    var body: some View {
        SettingsPane {
            SettingToggle(title: "Show status in menu bar", detail: "Shows the menu with the profile and mode switchers.", isOn: $s.showInMenuBar)
            Group {
                SettingToggle(title: "Numeric Traffic Rates", detail: "Show traffic rates as numerical values next to the menu bar icon.", isOn: $s.numericRates)
                SettingToggle(title: "Silent Mode", detail: "Indicate an active Silent Mode with a moon symbol in the menu bar.", isOn: $s.silentModeSymbol)
            }.disabled(!s.showInMenuBar)
        }
    }
}

// MARK: - Alert

struct AlertSettings: View {
    @ObservedObject private var s = AppSettings.shared
    var body: some View {
        SettingsPane {
            SettingToggle(title: "Confirm with Return and Escape",
                          detail: "Turn off this option to avoid accidental confirmation of the Rat alert. You can still click the buttons.",
                          isOn: $s.confirmWithReturn)
            VStack(alignment: .leading, spacing: 8) {
                Text("Alert Timeout").font(.system(size: 14, weight: .semibold))
                HStack {
                    Text("Answer automatically after")
                    Picker("", selection: $s.alertTimeout) {
                        Text("Never").tag(0); Text("10 seconds").tag(10); Text("30 seconds").tag(30); Text("60 seconds").tag(60); Text("5 minutes").tag(300)
                    }.labelsHidden().frame(width: 130)
                    Picker("", selection: $s.alertTimeoutAllows) { Text("Deny").tag(false); Text("Allow").tag(true) }
                        .labelsHidden().pickerStyle(.segmented).frame(width: 130).disabled(s.alertTimeout == 0)
                }
                Text("An alert nobody answers is answered once with the chosen verdict.").font(.callout).foregroundStyle(.secondary)
            }
        }
    }
}

// MARK: - Monitor

struct MonitorSettings: View {
    @ObservedObject private var s = AppSettings.shared
    @EnvironmentObject var ledger: Ledger
    var body: some View {
        SettingsPane {
            SettingToggle(title: "Include local network traffic", detail: "Show connections to devices on your own network (private address ranges).", isOn: $s.includeLocalNetwork)
            SettingToggle(title: "Include traffic of network extensions", detail: "List app extensions (such as share or VPN extensions) as separate rows marked EXT.", isOn: $s.includeNetworkExtensions)
            SettingToggle(title: "Include connections of other users",
                          detail: ledger.enforcer.helperInstalled ? "Processes of other accounts, seen through the background helper." : "Needs the background helper (Security tab); without it Rat only sees your own processes.",
                          isOn: $s.includeOtherUsers)
        }
    }
}

// MARK: - Automatic profile switching

struct ProfileSwitchingSettings: View {
    @EnvironmentObject var ledger: Ledger
    var body: some View {
        let rules = ledger.rules
        SettingsPane {
            SettingToggle(title: "Enable automatic profile switching", detail: "When joining a known network, an associated profile will be activated automatically.",
                          isOn: Binding(get: { rules.ruleSet.automaticProfileSwitching }, set: { rules.ruleSet.automaticProfileSwitching = $0 }))
            Group {
                VStack(alignment: .leading, spacing: 6) {
                    Text("When joining an unknown network:").foregroundStyle(.secondary)
                    Picker("", selection: Binding(get: { choice(rules.ruleSet.unknownNetworkAction) }, set: { rules.ruleSet.unknownNetworkAction = action($0, rules) })) {
                        Text("Ask").tag("ask")
                        Text("Do Nothing").tag("nothing")
                        ForEach(rules.ruleSet.profiles) { Text("Activate “\($0.name)”").tag($0.id.uuidString) }
                    }.labelsHidden().frame(width: 240)
                }
                if let net = rules.currentNetwork {
                    HStack {
                        Image(systemName: "wifi")
                        Text("Current network: \(net.name)")
                        Spacer()
                        Menu("Assign to profile…") {
                            ForEach(rules.ruleSet.profiles) { p in Button(p.name) { rules.rememberCurrentNetwork(profile: p.id) } }
                        }.fixedSize()
                    }
                }
                Text("Known networks").font(.system(size: 14, weight: .semibold))
                if rules.ruleSet.triggers.isEmpty {
                    Text("No networks assigned to a profile yet.").foregroundStyle(.secondary)
                }
                ForEach(rules.ruleSet.triggers) { t in
                    HStack {
                        Image(systemName: "wifi").frame(width: 20)
                        VStack(alignment: .leading) {
                            Text(t.name)
                            Text(rules.ruleSet.profiles.first { $0.id == t.profileID }?.name ?? "?").font(.caption).foregroundStyle(.secondary)
                        }
                        Spacer()
                        Button { rules.ruleSet.triggers.removeAll { $0.id == t.id } } label: { Image(systemName: "minus.circle") }.buttonStyle(.borderless)
                    }
                }
                Text("macOS only reveals Wi-Fi names to apps with Location access. Without it, networks are recognized by their gateway address.")
                    .font(.callout).foregroundStyle(.secondary)
            }.disabled(!rules.ruleSet.automaticProfileSwitching)
        }
    }

    private func choice(_ a: UnknownNetworkAction) -> String {
        switch a { case .ask, .deactivate: return "ask"; case .doNothing: return "nothing"; case .activate(let id): return id.uuidString }
    }

    private func action(_ c: String, _ rules: RulesModel) -> UnknownNetworkAction {
        switch c { case "ask": return .ask; case "nothing": return .doNothing; default: return UUID(uuidString: c).map { .activate($0) } ?? .ask }
    }
}

// MARK: - Security (firewall helper)

struct SecuritySettings: View {
    @EnvironmentObject var ledger: Ledger
    var body: some View {
        let enf = ledger.enforcer
        SettingsPane {
            Text("Firewall Helper").font(.system(size: 15, weight: .semibold))
            if enf.helperInstalled {
                if enf.helperOutdated {
                    Label("Installed, but an older version", systemImage: "exclamationmark.shield.fill").foregroundStyle(.orange)
                    Text("This helper still blocks server addresses for every app, which can break DNS and other apps. The current one only blocks the ports of denied apps.")
                        .font(.callout).foregroundStyle(.secondary)
                    Button(enf.busy ? "Updating…" : "Update Helper…") { enf.installHelper() }.disabled(enf.busy)
                } else {
                    Label("Installed: blocking is applied automatically", systemImage: "checkmark.shield.fill").foregroundStyle(.green)
                }
                SettingToggle(title: "Auto-apply firewall rules", detail: "Deny takes effect immediately. Turn off and nothing is blocked.",
                              isOn: Binding(get: { enf.autoApply }, set: { enf.autoApply = $0; ledger.refreshEnforcement() }))
                Label(ledger.systemWide ? "Seeing all processes system-wide" : "Waiting for the first system snapshot…", systemImage: "eye")
                    .foregroundStyle(.secondary)
                Button("Remove Helper…", role: .destructive) { enf.removeHelper() }.disabled(enf.busy)
            } else {
                Label("Not installed", systemImage: "shield.slash").foregroundStyle(.secondary)
                Text("Deny is enforced by the helper, which blocks the ports of a denied app’s connections with the macOS packet filter. Without it nothing is blocked and Rat sees only your own processes.")
                    .font(.callout).foregroundStyle(.secondary)
                Button(enf.busy ? "Installing…" : "Install Helper…") { enf.installHelper() }.disabled(enf.busy)
                Text("Installs two root LaunchDaemons after an administrator-password prompt: one blocks denied apps continuously, the other lists every process’s connections. “Remove Helper” uninstalls both and clears the firewall rules.")
                    .font(.caption).foregroundStyle(.secondary)
            }
            if let err = enf.lastError { Text(err).font(.caption).foregroundStyle(.red) }
            Divider()
            Text("Denying an app blocks the ports of all its processes as soon as the helper sees a socket (a few milliseconds). Server addresses are never blocked, so other apps are not affected. A first connection to a very close server can still get a few packets through; blocking before a connection opens needs Apple’s Network Extension entitlement.")
                .font(.callout).foregroundStyle(.secondary)
        }
    }
}

// MARK: - Notifications

struct NotificationSettings: View {
    @ObservedObject private var s = AppSettings.shared
    var body: some View {
        SettingsPane {
            Text("Connection Notifications").font(.system(size: 15, weight: .semibold))
            SettingToggle(title: "Silent Mode Connections", detail: "Shown when a connection was automatically allowed or denied in Silent Mode for the very first time.", isOn: $s.notifySilentConnections)
            SettingToggle(title: "Connection Alert Timeout", detail: "Shown when a connection alert was confirmed automatically after a timeout.", isOn: $s.notifyAlertTimeout)
            Text("Other Notifications").font(.system(size: 15, weight: .semibold)).padding(.top, 6)
            SettingToggle(title: "Automatic Profile Switching", detail: "Shown when a profile was activated automatically after joining a different network.", isOn: $s.notifyProfileSwitch)
            Button("Allow Notifications…") { Notifier.requestAuthorization() }
        }
    }
}

// MARK: - Update

struct UpdateSettings: View {
    @ObservedObject private var s = AppSettings.shared
    @State private var checking = false
    var body: some View {
        SettingsPane {
            SettingToggle(title: "Automatically check for updates", detail: "Looks for a new release on GitHub when Rat starts, at most once a day.", isOn: $s.autoCheckUpdates)
            SettingToggle(title: "Show pre-release versions", isOn: $s.showPreReleases)
            HStack {
                Spacer()
                VStack(spacing: 8) {
                    Button(checking ? "Checking…" : "Check Now") {
                        checking = true
                        Task { await UpdateChecker.check(); checking = false }
                    }.disabled(checking)
                    Text(lastChecked).font(.callout).foregroundStyle(s.lastUpdateCheckFailed ? .orange : .primary)
                }
                Spacer()
            }.padding(.top, 14)
        }
    }

    private var lastChecked: String {
        guard let d = s.lastUpdateCheck else { return "Not yet checked" }
        let f = DateFormatter(); f.dateStyle = .full; f.timeStyle = .short
        return "Last checked: \(f.string(from: d))" + (s.lastUpdateCheckFailed ? " (failed)" : "")
    }
}

// MARK: - Advanced

struct AdvancedSettings: View {
    @ObservedObject private var s = AppSettings.shared
    @EnvironmentObject var ledger: Ledger
    @State private var invalid: [String] = []

    var body: some View {
        let rules = ledger.rules
        SettingsPane {
            SettingToggle(title: "Mark new rules as unapproved",
                          detail: "New rules created via connection alert or Network Monitor are marked as unapproved with a blue dot in the Rules window.",
                          isOn: Binding(get: { rules.ruleSet.markNewRulesAsUnapproved }, set: { rules.ruleSet.markNewRulesAsUnapproved = $0 }))
            SettingToggle(title: "Approve rules automatically",
                          detail: "Selecting an unapproved rule in the Rules window approves this rule automatically. Turn off this option if you want to approve rules manually.",
                          isOn: $s.approveRulesAutomatically)
            HStack(spacing: 12) {
                Text("Traffic rate unit:").font(.system(size: 14))
                Picker("", selection: $s.trafficRateUnit) { ForEach(AppSettings.RateUnit.allCases) { Text($0.rawValue).tag($0) } }
                    .pickerStyle(.radioGroup).horizontalRadioGroupLayout().labelsHidden()
            }
            Text("Traffic rates are displayed in the menu bar and in the Network Monitor.").font(.callout).foregroundStyle(.secondary)
            VStack(alignment: .leading, spacing: 6) {
                Text("Additional IP Ranges in Local Network:").font(.system(size: 14))
                TextEditor(text: $s.additionalLocalRanges)
                    .font(.system(.body, design: .monospaced)).frame(height: 70)
                    .overlay(RoundedRectangle(cornerRadius: 6).stroke(invalid.isEmpty ? Color.gray.opacity(0.4) : .red))
                    .onChange(of: s.additionalLocalRanges) { _, new in invalid = LocalRanges.shared.set(new) }
                if !invalid.isEmpty { Text("Invalid address range: \(invalid.joined(separator: ", "))").font(.caption).foregroundStyle(.red) }
                else { Text("One range per line, e.g. 100.64.0.0/10").font(.caption).foregroundStyle(.secondary) }
            }
        }
    }
}
