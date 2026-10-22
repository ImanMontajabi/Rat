import Foundation
import os

private let logger = Logger(subsystem: "com.imanmontajabi.Rat", category: "store")

struct PersistedApp: Codable {
    var id: String
    var name: String
    var bundlePath: String?
    var isSystem: Bool
    var totalIn: UInt64
    var totalOut: UInt64
    var lastActive: Date
}

struct Bucket: Codable {
    var minute: Date
    var rx: Double
    var tx: Double
}

/// A connection the user denied; re-evaluated against the rules so the blocklist shrinks when a rule is removed.
struct DeniedEntry: Codable {
    var address: String
    var host: String
    var port: Int
    var proto: String
}

struct PersistedState: Codable {
    var apps: [PersistedApp] = []
    var denied: [String: [DeniedEntry]] = [:]
    var buckets: [Bucket] = []

    init(apps: [PersistedApp] = [], denied: [String: [DeniedEntry]] = [:], buckets: [Bucket] = []) {
        self.apps = apps; self.denied = denied; self.buckets = buckets
    }

    // Tolerant of state files written by earlier versions.
    init(from d: Decoder) throws {
        let c = try d.container(keyedBy: CodingKeys.self)
        apps = try c.decodeIfPresent([PersistedApp].self, forKey: .apps) ?? []
        denied = try c.decodeIfPresent([String: [DeniedEntry]].self, forKey: .denied) ?? [:]
        buckets = try c.decodeIfPresent([Bucket].self, forKey: .buckets) ?? []
    }
}

/// JSON state in ~/Library/Application Support/com.imanmontajabi.Rat (the only folder Rat writes to).
struct StateStore {
    let directory: URL
    var url: URL { directory.appendingPathComponent("state.json") }

    static func standard(base: URL? = nil) -> StateStore {
        let root = base ?? FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0].appendingPathComponent("com.imanmontajabi.Rat")
        try? FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        return StateStore(directory: root)
    }

    func load() -> PersistedState {
        guard let data = try? Data(contentsOf: url) else { return PersistedState() }
        let dec = JSONDecoder()
        dec.dateDecodingStrategy = .iso8601
        do { return try dec.decode(PersistedState.self, from: data) } catch {
            logger.error("state unreadable, starting fresh: \(error.localizedDescription, privacy: .public)")
            return PersistedState()
        }
    }

    func save(_ state: PersistedState) {
        do {
            let enc = JSONEncoder()
            enc.dateEncodingStrategy = .iso8601
            try enc.encode(state).write(to: url, options: .atomic)
        } catch {
            logger.error("state save failed: \(error.localizedDescription, privacy: .public)")
        }
    }
}
