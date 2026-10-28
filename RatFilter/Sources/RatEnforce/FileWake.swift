import Foundation
import Darwin

/// Wakes the daemon's loop as soon as one of the files Rat hands it changes, so a deny is enforced on the next pass
/// rather than after the idle sleep (up to 0.25 s, during which a stream into a socket buffer that is not full yet
/// kept arriving). Rat replaces its files by renaming a new one over them, which writes their folder; a file written
/// in place (`echo … > file`) changes only itself, so both the folders and the files are watched, and the files are
/// watched again whenever a folder changes (a replaced file is a new inode). The timed sleep stays the fallback: a
/// folder that cannot be opened, or one replaced as a whole, only makes the wakeup late, as before.
final class FileWake {
    private let files: [String]
    private let queue = DispatchQueue(label: "com.imanmontajabi.rat.enforcer.wake")
    private let changed = DispatchSemaphore(value: 0)
    private var folderSources: [DispatchSourceFileSystemObject] = []
    private var fileSources: [DispatchSourceFileSystemObject] = []

    init(files: [String]) {
        self.files = files
        for folder in Set(files.map { ($0 as NSString).deletingLastPathComponent }) {
            guard let s = watch(folder, [.write, .delete, .rename]) else { continue }
            s.setEventHandler { [weak self] in self?.rearmFiles(); self?.changed.signal() }
            folderSources.append(s)
            s.resume()
        }
        queue.sync { rearmFiles() }
    }

    deinit {
        (folderSources + fileSources).forEach { $0.cancel() }
    }

    /// How many folders and files are watched (0 when none could be opened).
    var watchedCount: Int { queue.sync { folderSources.count + fileSources.count } }

    /// Sleeps for at most `interval`. Returns true when a watched file or folder changed (at once, then).
    func wait(_ interval: TimeInterval) -> Bool {
        guard changed.wait(timeout: .now() + interval) == .success else { return false }
        // Several events for one change (a rename writes the folder and deletes the old file) wake once.
        while changed.wait(timeout: .now()) == .success {}
        return true
    }

    /// The files' own sources, opened again (on `queue`).
    private func rearmFiles() {
        fileSources.forEach { $0.cancel() }
        fileSources = files.compactMap { path in
            guard let s = watch(path, [.write, .extend, .delete, .rename, .attrib]) else { return nil }
            s.setEventHandler { [weak self] in self?.changed.signal() }
            s.resume()
            return s
        }
    }

    /// A source on `path`, opened for events only (it never reads the file, and does not keep a deleted file alive).
    private func watch(_ path: String, _ mask: DispatchSource.FileSystemEvent) -> DispatchSourceFileSystemObject? {
        let fd = open(path, O_EVTONLY | O_CLOEXEC)
        guard fd >= 0 else { return nil }
        let s = DispatchSource.makeFileSystemObjectSource(fileDescriptor: fd, eventMask: mask, queue: queue)
        s.setCancelHandler { close(fd) }
        return s
    }
}
