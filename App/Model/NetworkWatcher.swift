import Foundation
import CoreWLAN
import SystemConfiguration

/// Identifies the network the Mac is on, for automatic profile switching.
/// Uses the Wi-Fi name when macOS reveals it (it needs Location access) and otherwise the default gateway.
enum NetworkWatcher {
    struct Network: Equatable {
        var signature: String
        var name: String
    }

    static func current() -> Network? {
        if let ssid = CWWiFiClient.shared().interface()?.ssid(), !ssid.isEmpty { return Network(signature: ssid, name: ssid) }
        guard let store = SCDynamicStoreCreate(nil, "Rat" as CFString, nil, nil),
              let info = SCDynamicStoreCopyValue(store, "State:/Network/Global/IPv4" as CFString) as? [String: Any],
              let router = info["Router"] as? String else { return nil }
        return Network(signature: "gateway:\(router)", name: "Network via \(router)")
    }
}
