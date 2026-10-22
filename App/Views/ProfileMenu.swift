import SwiftUI

/// Toolbar control for switching the active profile and silent mode.
struct ProfileMenu: View {
    @EnvironmentObject var ledger: Ledger

    var body: some View {
        let rules = ledger.rules
        Menu {
            Section("Profile") {
                ForEach(rules.ruleSet.profiles) { p in
                    Button { rules.activate(p.id) } label: {
                        Label(p.name, systemImage: p.id == rules.ruleSet.activeProfileID ? "checkmark" : p.symbol)
                    }
                }
            }
            Section("Mode") {
                ForEach(SilentMode.allCases) { m in
                    Button { rules.silentMode = m } label: { Label(m.rawValue, systemImage: rules.silentMode == m ? "checkmark" : "circle") }
                }
            }
        } label: {
            HStack(spacing: 4) {
                Image(systemName: rules.activeProfile?.symbol ?? "person.crop.circle")
                Text(rules.activeProfile?.name ?? "Profile").font(.callout)
                if rules.silentMode != .off { Image(systemName: "moon.fill").font(.caption).foregroundStyle(.yellow) }
            }
        }
        .menuStyle(.borderlessButton).menuIndicator(.hidden).fixedSize()
        .help("Switch profile or mode")
    }
}
