import Foundation
import NetworkExtension
import Security
import Darwin
import RatFilterCore

/// Content-filter provider. Must be shipped inside a system extension that has the
/// `com.apple.developer.networking.networkextension = content-filter-provider-systemextension`
/// entitlement (same mechanism Little Snitch's network extension uses).
///
/// Flow: handleNewFlow -> evaluate rules -> allow / drop immediately, or pause the flow,
/// ask the UI process over XPC, then resumeFlow with the user's verdict.
open class RatFilterProvider: NEFilterDataProvider {
    public let engine = RuleEngine()
    /// Set by the host to prompt the user; call `reply` exactly once.
    public var askUser: ((Connection, @escaping (Verdict, Rule?) -> Void) -> Void)?

    private var pending: [UUID: NEFilterFlow] = [:]
    private let queue = DispatchQueue(label: "rat.filter.pending")

    open override func startFilter(completionHandler: @escaping (Error?) -> Void) {
        // Intercept all outbound TCP/UDP; inbound handled by default policy.
        let rule = NENetworkRule(remoteNetwork: nil, remotePrefix: 0, localNetwork: nil,
                                 localPrefix: 0, protocol: .any, direction: .outbound)
        let settings = NEFilterSettings(rules: [NEFilterRule(networkRule: rule, action: .filterData)],
                                        defaultAction: .allow)
        apply(settings, completionHandler: completionHandler)
    }

    open override func stopFilter(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        completionHandler()
    }

    open override func handleNewFlow(_ flow: NEFilterFlow) -> NEFilterNewFlowVerdict {
        guard let conn = Self.connection(from: flow) else { return .allow() }
        switch engine.evaluate(conn) {
        case .allow: return .allow()
        case .deny: return .drop()
        case .ask:
            guard let askUser else { return .allow() }
            let token = UUID()
            queue.sync { pending[token] = flow }
            askUser(conn) { [weak self] verdict, rule in
                guard let self else { return }
                if let rule { self.engine.add(rule) }
                let flow = self.queue.sync { self.pending.removeValue(forKey: token) }
                if let flow {
                    self.resumeFlow(flow, with: verdict == .allow ? NEFilterNewFlowVerdict.allow() : NEFilterNewFlowVerdict.drop())
                }
            }
            return .pause()
        }
    }

    static func connection(from flow: NEFilterFlow) -> Connection? {
        guard let socket = flow as? NEFilterSocketFlow,
              let remote = socket.remoteEndpoint as? NWHostEndpoint else { return nil }
        let token = flow.sourceAppAuditToken
        let path = token.flatMap { Self.path(for: $0) } ?? "unknown"
        let (signingID, teamID) = token.map(Self.signingInfo(for:)) ?? (nil, nil)
        let proc = ProcessIdentity(signingID: signingID, teamID: teamID, path: path)
        let proto: Connection.Proto = socket.socketProtocol == IPPROTO_UDP ? .udp : .tcp
        return Connection(process: proc, host: socket.remoteHostname,
                          address: remote.hostname, port: Int(remote.port) ?? 0, proto: proto)
    }

    private static func path(for tokenData: Data) -> String? {
        guard tokenData.count == MemoryLayout<audit_token_t>.size else { return nil }
        let pid = tokenData.withUnsafeBytes { $0.load(as: audit_token_t.self) }.val.5
        var buf = [CChar](repeating: 0, count: 4096)
        return proc_pidpath(Int32(pid), &buf, UInt32(buf.count)) > 0 ? String(cString: buf) : nil
    }

    /// Resolve signing identifier + team ID from the flow's audit token (sourceAppIdentifier is iOS-only).
    private static func signingInfo(for tokenData: Data) -> (String?, String?) {
        var code: SecCode?
        let attrs = [kSecGuestAttributeAudit: tokenData] as CFDictionary
        guard SecCodeCopyGuestWithAttributes(nil, attrs, [], &code) == errSecSuccess, let code else { return (nil, nil) }
        var staticCode: SecStaticCode?
        guard SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess, let staticCode else { return (nil, nil) }
        var info: CFDictionary?
        guard SecCodeCopySigningInformation(staticCode, SecCSFlags(rawValue: kSecCSSigningInformation), &info) == errSecSuccess,
              let dict = info as? [String: Any] else { return (nil, nil) }
        return (dict[kSecCodeInfoIdentifier as String] as? String, dict[kSecCodeInfoTeamIdentifier as String] as? String)
    }
}
