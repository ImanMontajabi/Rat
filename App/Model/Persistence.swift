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

struct PersistedState: Codable {
    var apps: [PersistedApp] = []
    var blocked: [String: [String]] = [:]
    var buckets: [Bucket] = []
}

/// JSON state in ~/Library/Application Support/Rat.
struct StateStore {
    let directory: URL
    var url: URL { directory.appendingPathComponent("state.json") }

    static func standard() -> StateStore {
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0].appendingPathComponent("Rat")
        try? FileManager.default.createDirectory(at: base, withIntermediateDirectories: true)
        return StateStore(directory: base)
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
