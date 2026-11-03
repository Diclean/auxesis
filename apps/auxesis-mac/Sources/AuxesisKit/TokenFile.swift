// Guarded read of the auxd bearer-token file (~/.auxesis/api.token).
//
// Mirrors the Rust-side guarded-home reads on the Swift side, TOCTOU-free:
//   1. the Auxesis home directory itself is `lstat`ed — a symlinked home is
//      refused, and the directory must be owned by the user and not
//      group/world writable (nobody else may replace the token);
//   2. the file is opened `O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC` — a
//      symlink at the path fails with ELOOP (never followed), and a FIFO
//      cannot block the open;
//   3. kind/size/owner/mode are read with `fstat` on the *same* descriptor
//      that was opened — there is no lstat-then-open window to win;
//   4. only a regular file is accepted (no FIFO, device, directory);
//   5. size ≤ `maxBytes` (4 KiB, the daemon's own cap), owner is the user,
//      and mode has no group/world bits;
//   6. the read is bounded again on the same fd, in case the file grew.
//
// A missing path is `.missing` ("no token yet"), never an error: the app
// starts and explains instead of hanging.
import Darwin
import Foundation

public enum TokenFileProblem: Equatable {
    case missing
    case symlink
    case notRegularFile
    case tooLarge
    case permissions(String)
    case unreadable
    case invalidEncoding
    /// The file (or the Auxesis home) belongs to another user.
    case wrongOwner
    /// The Auxesis home is not a real directory, or is group/world writable.
    case unsafeDirectory
}

public enum TokenFileResult: Equatable {
    case ok(String)
    case problem(TokenFileProblem)
}

public enum TokenFile {
    /// The daemon caps its token file at 4 KiB; the client mirrors that.
    public static let maxBytes = 4096
    /// Longest accepted token string (the daemon uses the same bound).
    public static let maxTokenChars = 256

    public static func read(at url: URL) -> TokenFileResult {
        read(at: url, expectedOwner: getuid())
    }

    /// `expectedOwner` is injectable so tests can exercise the *file*
    /// ownership refusal without running as another user; the home directory
    /// is always checked against the real user (`directoryProblem` has its
    /// own seam).
    static func read(at url: URL, expectedOwner: uid_t) -> TokenFileResult {
        if let problem = directoryProblem(for: url, expectedOwner: getuid()) {
            return .problem(problem)
        }

        let fd = open(url.path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
        if fd < 0 {
            switch errno {
            case ELOOP: return .problem(.symlink)
            case ENOENT: return .problem(.missing)
            default: return .problem(.unreadable)
            }
        }
        defer { close(fd) }

        // Everything below inspects the descriptor actually opened: no second
        // path lookup, so a rename/symlink swap cannot change what is read.
        var info = stat()
        guard fstat(fd, &info) == 0 else { return .problem(.unreadable) }
        let kind = info.st_mode & mode_t(S_IFMT)
        if kind == mode_t(S_IFLNK) { return .problem(.symlink) }
        if kind != mode_t(S_IFREG) { return .problem(.notRegularFile) }
        if info.st_uid != expectedOwner { return .problem(.wrongOwner) }
        let mode = info.st_mode & 0o777
        // fs_guard.rs parity: no group/world bits at all, and owner read/write
        // only (the daemon writes 0600).
        guard mode & 0o077 == 0, mode & 0o700 == 0o600 else {
            return .problem(.permissions(String(mode, radix: 8)))
        }
        if info.st_size > off_t(maxBytes) { return .problem(.tooLarge) }

        var buffer = [UInt8](repeating: 0, count: maxBytes + 1)
        var total = 0
        var readFailed = false
        buffer.withUnsafeMutableBytes { raw in
            guard let base = raw.baseAddress else { return }
            while total < raw.count {
                let count = Darwin.read(fd, base.advanced(by: total), raw.count - total)
                if count < 0 {
                    if errno == EINTR { continue }
                    readFailed = true
                    return
                }
                if count == 0 { break }
                total += count
            }
        }
        if readFailed { return .problem(.unreadable) }
        if total > maxBytes { return .problem(.tooLarge) }

        guard let text = String(data: Data(buffer[0..<total]), encoding: .utf8) else {
            return .problem(.invalidEncoding)
        }
        let token = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !token.isEmpty, token.count <= maxTokenChars else {
            return .problem(.invalidEncoding)
        }
        // The daemon only ever writes lowercase hex; anything that is not
        // printable ASCII is not our token.
        guard token.unicodeScalars.allSatisfy({ $0.value >= 0x21 && $0.value <= 0x7E }) else {
            return .problem(.invalidEncoding)
        }
        return .ok(token)
    }

    /// The directory that holds the token must be the user's own and closed to
    /// group/world writes; a symlinked home is refused outright. Exposed to
    /// tests: creating a directory owned by another uid needs root, so the
    /// expected owner is injectable.
    static func directoryProblem(for url: URL, expectedOwner: uid_t) -> TokenFileProblem? {
        var info = stat()
        guard lstat(url.deletingLastPathComponent().path, &info) == 0 else { return .missing }
        let kind = info.st_mode & mode_t(S_IFMT)
        guard kind == mode_t(S_IFDIR) else { return .unsafeDirectory }
        if info.st_uid != expectedOwner { return .wrongOwner }
        if info.st_mode & mode_t(0o022) != 0 { return .unsafeDirectory }
        return nil
    }
}
