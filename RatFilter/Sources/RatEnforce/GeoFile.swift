import Darwin
import Foundation
import RatGeo

/// Opens the City database a country rule needs (`DaemonRules.geoDatabase`). Rat names the file in a file the user
/// can write, and the daemon runs as root, so it reads only a file the user could read anyway: a regular file (no
/// symlink followed) that the user owns and can read, or that everyone can read. It is mapped, not read: the pages a
/// lookup touches are all that come into memory, and the reader treats the bytes as untrusted (`MMDB`).
public enum GeoFile {
    /// Larger than any City database (DB-IP's is about 130 MB).
    static let maxSize: Int64 = 1 << 30

    public static func open(_ path: String, ownerUID: uid_t?) -> GeoIP? {
        let fd = Darwin.open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { return nil }
        defer { close(fd) }
        var st = stat()
        guard fstat(fd, &st) == 0, readable(st, by: ownerUID), st.st_size > 0, st.st_size <= maxSize else { return nil }
        let size = Int(st.st_size)
        guard let base = mmap(nil, size, PROT_READ, MAP_PRIVATE, fd, 0), base != MAP_FAILED else { return nil }
        let data = Data(bytesNoCopy: base, count: size, deallocator: .unmap)
        return (try? MMDB(data: data)).map(GeoIP.init(db:))
    }

    /// What tells one file at a path from the next.
    public struct Identity: Equatable { var path: String; var device: Int32; var inode: UInt64 }

    public static func identity(_ path: String) -> Identity {
        var st = stat()
        return lstat(path, &st) == 0 ? Identity(path: path, device: st.st_dev, inode: st.st_ino) : Identity(path: path, device: 0, inode: 0)
    }

    /// A regular file the user (`ownerUID`) owns and can read, or one everyone can read.
    static func readable(_ st: stat, by ownerUID: uid_t?) -> Bool {
        guard st.st_mode & S_IFMT == S_IFREG else { return false }
        if st.st_mode & S_IROTH != 0 { return true }
        if let ownerUID, st.st_uid == ownerUID, st.st_mode & S_IRUSR != 0 { return true }
        return false
    }
}
