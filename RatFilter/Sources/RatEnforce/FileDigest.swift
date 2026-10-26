import CryptoKit
import Foundation

/// SHA-256 of a file, as lowercase hex. Rat compares the helper in its bundle with the installed one and with the one
/// the daemon runs (`EnforcerStatus.executableSHA256`), so an app update with a changed helper always asks for
/// Update Helper, whatever its version number says.
public enum FileDigest {
    public static func sha256(atPath path: String) -> String? {
        guard let h = FileHandle(forReadingAtPath: path) else { return nil }
        defer { try? h.close() }
        var hasher = SHA256()
        do {
            // nil (or empty data) at the end of the file.
            while let chunk = try h.read(upToCount: 1 << 20), !chunk.isEmpty { hasher.update(data: chunk) }
        } catch { return nil }
        return hasher.finalize().map { String(format: "%02x", $0) }.joined()
    }
}
