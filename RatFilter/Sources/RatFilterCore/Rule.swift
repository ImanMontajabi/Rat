import Foundation

/// Outcome for a connection. `ask` means: pause the flow and prompt the user.
public enum Verdict: String, Codable, Sendable {
    case allow, deny, ask
}

/// How long a rule created from an alert lives.
public enum Lifetime: String, Codable, Sendable, CaseIterable {
    case once        // never stored: applies to the one connection that raised the alert
    case untilQuit   // kept in memory, dropped when Rat quits
    case forever
}

/// Identifies the process behind a flow. Little Snitch matches on code requirement / team ID
/// rather than path alone, so renamed binaries don't escape rules.
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

public struct Rule: Codable, Identifiable, Sendable, Equatable {
    public var id: UUID
    public var verdict: Verdict
    /// Application bundle (or executable) path; matches the path itself and anything inside it.
    public var processPath: String?
    public var signingID: String?
    public var teamID: String?
    /// "example.com" matches the domain and subdomains; "*" or nil = any remote.
    public var remoteDomain: String?
    /// Exact hostname, no subdomains.
    public var remoteHost: String?
    public var remoteAddress: String?
    public var ports: ClosedRange<Int>?
    public var proto: Connection.Proto?
    public var enabled: Bool
    /// Review marker. Rules created from alerts while "mark new rules as unapproved" is on stay active but
    /// carry a blue dot until approved; imported rules also arrive disabled, so they do nothing until approved.
    public var approved: Bool
    public var lifetime: Lifetime
    /// nil = active in every profile.
    public var profileID: UUID?
    public var groupID: UUID?
    public var createdAt: Date
    public var note: String?

    public init(id: UUID = UUID(), verdict: Verdict, processPath: String? = nil, signingID: String? = nil, teamID: String? = nil,
                remoteDomain: String? = nil, remoteHost: String? = nil, remoteAddress: String? = nil,
                ports: ClosedRange<Int>? = nil, proto: Connection.Proto? = nil, enabled: Bool = true, approved: Bool = true,
                lifetime: Lifetime = .forever, profileID: UUID? = nil, groupID: UUID? = nil,
                createdAt: Date = Date(), note: String? = nil) {
        self.id = id; self.verdict = verdict; self.processPath = processPath; self.signingID = signingID; self.teamID = teamID
        self.remoteDomain = remoteDomain; self.remoteHost = remoteHost; self.remoteAddress = remoteAddress
        self.ports = ports; self.proto = proto; self.enabled = enabled; self.approved = approved
        self.lifetime = lifetime; self.profileID = profileID; self.groupID = groupID; self.createdAt = createdAt; self.note = note
    }

    // Tolerant decoding so rule files written by older versions (and hand edits) still load.
    enum CodingKeys: String, CodingKey {
        case id, verdict, processPath, signingID, teamID, remoteDomain, remoteHost, remoteAddress, ports, proto
        case enabled, approved, lifetime, profileID, groupID, createdAt, note
    }

    public init(from d: Decoder) throws {
        let c = try d.container(keyedBy: CodingKeys.self)
        id = try c.decodeIfPresent(UUID.self, forKey: .id) ?? UUID()
        verdict = try c.decode(Verdict.self, forKey: .verdict)
        processPath = try c.decodeIfPresent(String.self, forKey: .processPath)
        signingID = try c.decodeIfPresent(String.self, forKey: .signingID)
        teamID = try c.decodeIfPresent(String.self, forKey: .teamID)
        remoteDomain = try c.decodeIfPresent(String.self, forKey: .remoteDomain)
        remoteHost = try c.decodeIfPresent(String.self, forKey: .remoteHost)
        remoteAddress = try c.decodeIfPresent(String.self, forKey: .remoteAddress)
        ports = try c.decodeIfPresent(ClosedRange<Int>.self, forKey: .ports)
        proto = try c.decodeIfPresent(Connection.Proto.self, forKey: .proto)
        enabled = try c.decodeIfPresent(Bool.self, forKey: .enabled) ?? true
        approved = try c.decodeIfPresent(Bool.self, forKey: .approved) ?? true
        lifetime = try c.decodeIfPresent(Lifetime.self, forKey: .lifetime) ?? .forever
        profileID = try c.decodeIfPresent(UUID.self, forKey: .profileID)
        groupID = try c.decodeIfPresent(UUID.self, forKey: .groupID)
        createdAt = try c.decodeIfPresent(Date.self, forKey: .createdAt) ?? Date(timeIntervalSince1970: 0)
        note = try c.decodeIfPresent(String.self, forKey: .note)
    }

    /// Higher = more specific. Specific rules beat general ones; at equal specificity deny beats allow.
    public var specificity: Int {
        var s = 0
        if processPath != nil { s += 4 } else if signingID != nil { s += 4 } else if teamID != nil { s += 2 }
        if remoteAddress != nil { s += 5 }
        if remoteHost != nil { s += 4 } else if let d = remoteDomain, d != "*" { s += 3 }
        if ports != nil { s += 2 }
        if proto != nil { s += 1 }
        return s
    }

    /// Human-readable scope, e.g. "Any process → example.com:443".
    public var summary: String {
        let who = processPath.map { ($0 as NSString).lastPathComponent.replacingOccurrences(of: ".app", with: "") }
            ?? signingID ?? teamID.map { "Team \($0)" } ?? "Any process"
        var what = remoteAddress ?? remoteHost ?? remoteDomain.flatMap { $0 == "*" ? nil : "*.\($0)" } ?? "any server"
        if let ports { what += ports.lowerBound == ports.upperBound ? ":\(ports.lowerBound)" : ":\(ports.lowerBound)-\(ports.upperBound)" }
        if let proto { what += " (\(proto.rawValue.uppercased()))" }
        return "\(who) → \(what)"
    }

    public func matches(_ c: Connection) -> Bool {
        guard enabled else { return false }
        if let processPath, !(c.process.path == processPath || c.process.path.hasPrefix(processPath + "/")) { return false }
        if let signingID, signingID != c.process.signingID { return false }
        if let teamID, teamID != c.process.teamID { return false }
        if let proto, proto != c.proto { return false }
        if let ports, !ports.contains(c.port) { return false }
        if let remoteAddress, remoteAddress != c.address { return false }
        if let remoteHost, remoteHost.lowercased() != c.host?.lowercased() { return false }
        if let d = remoteDomain, d != "*" {
            guard let host = c.host?.lowercased() else { return false }
            let dom = d.lowercased()
            if host != dom && !host.hasSuffix("." + dom) { return false }
        }
        return true
    }
}
