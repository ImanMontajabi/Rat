import Foundation

/// Outcome for a connection. `ask` means: pause the flow and prompt the user.
public enum Verdict: String, Codable, Sendable {
    case allow, deny, ask
}

/// Identifies the process behind a flow. Little Snitch matches on code
/// requirement / team ID rather than path alone, so renamed binaries don't escape rules.
public struct ProcessIdentity: Codable, Hashable, Sendable {
    public var signingID: String?
    public var teamID: String?
    public var path: String

    public init(signingID: String? = nil, teamID: String? = nil, path: String) {
        self.signingID = signingID
        self.teamID = teamID
        self.path = path
    }
}

public struct Connection: Sendable {
    public var process: ProcessIdentity
    public var host: String?      // remote hostname if known (SNI / DNS), else nil
    public var address: String    // remote IP
    public var port: Int
    public var proto: Proto

    public enum Proto: String, Codable, Sendable { case tcp, udp }

    public init(process: ProcessIdentity, host: String? = nil, address: String, port: Int, proto: Proto = .tcp) {
        self.process = process
        self.host = host
        self.address = address
        self.port = port
        self.proto = proto
    }
}

public struct Rule: Codable, Identifiable, Sendable {
    public var id: UUID
    public var verdict: Verdict
    /// nil = any process
    public var signingID: String?
    public var teamID: String?
    /// "example.com" matches the domain and subdomains; "*" or nil = any remote.
    public var remoteDomain: String?
    public var remoteAddress: String?
    public var ports: ClosedRange<Int>?
    public var proto: Connection.Proto?
    public var enabled: Bool
    /// Unapproved rules (e.g. from a profile import) are ignored until accepted.
    public var approved: Bool

    public init(id: UUID = UUID(), verdict: Verdict, signingID: String? = nil, teamID: String? = nil,
                remoteDomain: String? = nil, remoteAddress: String? = nil, ports: ClosedRange<Int>? = nil,
                proto: Connection.Proto? = nil, enabled: Bool = true, approved: Bool = true) {
        self.id = id; self.verdict = verdict; self.signingID = signingID; self.teamID = teamID
        self.remoteDomain = remoteDomain; self.remoteAddress = remoteAddress
        self.ports = ports; self.proto = proto; self.enabled = enabled; self.approved = approved
    }

    /// Higher = more specific. Specific rules beat general ones; at equal specificity deny beats allow.
    var specificity: Int {
        var s = 0
        if signingID != nil { s += 4 } else if teamID != nil { s += 2 }
        if remoteAddress != nil { s += 4 }
        if let d = remoteDomain, d != "*" { s += 3 }
        if ports != nil { s += 2 }
        if proto != nil { s += 1 }
        return s
    }

    func matches(_ c: Connection) -> Bool {
        guard enabled, approved else { return false }
        if let signingID, signingID != c.process.signingID { return false }
        if let teamID, teamID != c.process.teamID { return false }
        if let proto, proto != c.proto { return false }
        if let ports, !ports.contains(c.port) { return false }
        if let remoteAddress, remoteAddress != c.address { return false }
        if let d = remoteDomain, d != "*" {
            guard let host = c.host?.lowercased() else { return false }
            let dom = d.lowercased()
            if host != dom && !host.hasSuffix("." + dom) { return false }
        }
        return true
    }
}
