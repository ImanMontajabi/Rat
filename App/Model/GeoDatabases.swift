import Foundation
import os

private let logger = Logger(subsystem: "com.imanmontajabi.Rat", category: "geo")

/// The GeoIP database files the user chose (Settings > GeoIP): a newer DB-IP Lite file, or their own MaxMind
/// GeoLite2/GeoIP2 City or ASN file. Chosen files are copied into the data folder; without one, or when it fails
/// to load, the bundled DB-IP file is used.
@MainActor
final class GeoDatabases: ObservableObject {
    struct Info: Equatable {
        var custom: Bool
        var fileName: String
        var type: String
        var built: Date?
    }

    @Published private(set) var info: [GeoService.Kind: Info] = [:]
    @Published private(set) var busy: GeoService.Kind?
    @Published var lastError: String?

    /// A database older than this is flagged: DB-IP publishes new files every month.
    static let staleAfter: TimeInterval = 90 * 86_400

    let folder: URL
    private let geo: GeoService
    private let defaults: UserDefaults
    private let download: (URL) async throws -> URL

    init(directory: URL, geo: GeoService, defaults: UserDefaults = Preferences.store,
         download: @escaping (URL) async throws -> URL = GeoDatabases.urlSessionDownload) {
        folder = directory.appendingPathComponent("GeoIP", isDirectory: true)
        self.geo = geo
        self.defaults = defaults
        self.download = download
        for kind in GeoService.Kind.allCases {
            guard let name = defaults.string(forKey: Self.key(kind)) else { continue }
            let path = folder.appendingPathComponent(name).path
            do { try geo.use(kind, path: path) } catch {
                // Back to the bundled file; the choice is kept so the pane can say what went wrong.
                lastError = "Your \(Self.title(kind)) file could not be loaded (\(error.localizedDescription)); the bundled one is used."
                logger.error("custom \(kind.rawValue, privacy: .public) database failed to load")
            }
        }
        refresh()
    }

    static func key(_ kind: GeoService.Kind) -> String { kind == .city ? "geoCityFile" : "geoASNFile" }
    static func title(_ kind: GeoService.Kind) -> String { kind == .city ? "city" : "network (ASN)" }

    func isStale(_ i: Info, now: Date = Date()) -> Bool { i.built.map { now.timeIntervalSince($0) > Self.staleAfter } ?? false }

    private func refresh() {
        var out: [GeoService.Kind: Info] = [:]
        for kind in GeoService.Kind.allCases {
            guard let l = geo.loadedFile(kind) else { continue }
            out[kind] = Info(custom: l.path.hasPrefix(folder.path + "/"), fileName: (l.path as NSString).lastPathComponent, type: l.type, built: l.built)
        }
        info = out
    }

    /// Validates a file, copies it into the data folder under a new name (a file in use is never overwritten: it
    /// is memory-mapped) and switches to it. The previous custom file is deleted afterwards.
    func choose(_ kind: GeoService.Kind, file: URL) throws {
        _ = try GeoService.validate(kind, path: file.path)
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
        let name = "\(kind.rawValue)-\(Int(Date().timeIntervalSince1970))-\(UUID().uuidString.prefix(6)).mmdb"
        let dest = folder.appendingPathComponent(name)
        try FileManager.default.copyItem(at: file, to: dest)
        do { try geo.use(kind, path: dest.path) } catch {
            try? FileManager.default.removeItem(at: dest)
            throw error
        }
        let previous = defaults.string(forKey: Self.key(kind))
        defaults.set(name, forKey: Self.key(kind))
        if let previous, previous != name { try? FileManager.default.removeItem(at: folder.appendingPathComponent(previous)) }
        lastError = nil
        refresh()
    }

    /// Back to the file bundled with Rat.
    func useBundled(_ kind: GeoService.Kind) {
        guard let p = GeoService.bundledPath(kind.bundledName, env: kind == .city ? "RAT_GEOIP_DB" : "RAT_GEOIP_ASN_DB") else {
            lastError = "No bundled \(Self.title(kind)) database in this build."; return
        }
        do { try geo.use(kind, path: p) } catch { lastError = error.localizedDescription; return }
        if let previous = defaults.string(forKey: Self.key(kind)) { try? FileManager.default.removeItem(at: folder.appendingPathComponent(previous)) }
        defaults.removeObject(forKey: Self.key(kind))
        lastError = nil
        refresh()
    }

    /// DB-IP's monthly Lite files (CC BY 4.0), newest first: this month's may not be out yet.
    static func dbipURLs(_ kind: GeoService.Kind, now: Date = Date()) -> [URL] {
        var cal = Calendar(identifier: .gregorian); cal.timeZone = TimeZone(identifier: "UTC")!
        return (0..<2).compactMap { back in
            guard let d = cal.date(byAdding: .month, value: -back, to: now) else { return nil }
            let c = cal.dateComponents([.year, .month], from: d)
            return URL(string: String(format: "https://download.db-ip.com/free/dbip-%@-lite-%04d-%02d.mmdb.gz", kind.rawValue, c.year!, c.month!))
        }
    }

    /// Downloads the newest DB-IP Lite file of a kind (only when the user clicks: the file is 10 to 60 MB),
    /// unpacks it and switches to it.
    func downloadLatest(_ kind: GeoService.Kind) async {
        guard busy == nil else { return }
        busy = kind
        defer { busy = nil }
        var failure = "Could not download the DB-IP database."
        for url in Self.dbipURLs(kind) {
            do {
                let gz = try await download(url)
                let mmdb = try await Self.gunzip(gz)
                defer { try? FileManager.default.removeItem(at: mmdb); try? FileManager.default.removeItem(at: gz) }
                try choose(kind, file: mmdb)
                return
            } catch {
                failure = error.localizedDescription
            }
        }
        lastError = failure
    }

    static func urlSessionDownload(_ url: URL) async throws -> URL {
        let (tmp, response) = try await URLSession.shared.download(from: url)
        guard (response as? HTTPURLResponse)?.statusCode == 200 else {
            try? FileManager.default.removeItem(at: tmp)
            throw URLError(.fileDoesNotExist)
        }
        let dest = FileManager.default.temporaryDirectory.appendingPathComponent("rat-geo-\(UUID().uuidString).mmdb.gz")
        try FileManager.default.moveItem(at: tmp, to: dest)
        return dest
    }

    /// Unpacks a .gz with the system's gunzip.
    static func gunzip(_ gz: URL) async throws -> URL {
        let out = gz.deletingPathExtension()
        try await Task.detached {
            let p = Process()
            p.executableURL = URL(fileURLWithPath: "/usr/bin/gunzip")
            p.arguments = ["-f", gz.path]
            p.standardError = FileHandle.nullDevice
            try p.run()
            p.waitUntilExit()
            guard p.terminationStatus == 0, FileManager.default.fileExists(atPath: out.path) else { throw GeoService.Invalid.notADatabase }
        }.value
        return out
    }
}
