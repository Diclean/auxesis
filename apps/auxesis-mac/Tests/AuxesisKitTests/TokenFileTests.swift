// Token file safety: 0600, no symlinks, no FIFOs, bounded reads — the same
// discipline as the Rust-side guarded-home reads (aux-core).
import Darwin
import Testing
@testable import AuxesisKit

@objcMembers @MainActor final class TokenFileTests: XCTestCase {
    private func tempDirectory() throws -> URL {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("auxesis-token-tests-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        return url
    }

    func testMissingFileIsHonestNotAnError() throws {
        let dir = try tempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        XCTAssertEqual(TokenFile.read(at: dir.appendingPathComponent("absent")), .problem(.missing))
    }

    func testPrivateTokenReads() throws {
        let dir = try tempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let path = dir.appendingPathComponent("api.token")
        try Data("deadbeef\n".utf8).write(to: path)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: path.path)
        XCTAssertEqual(TokenFile.read(at: path), .ok("deadbeef"))
    }

    func testWorldReadableFileIsRefused() throws {
        let dir = try tempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let path = dir.appendingPathComponent("api.token")
        try Data("deadbeef".utf8).write(to: path)
        try FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: path.path)
        guard case .problem(.permissions) = TokenFile.read(at: path) else {
            return XCTFail("0644 must be refused")
        }
    }

    func testSymlinkIsRefusedWithoutFollowingIt() throws {
        let dir = try tempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let target = dir.appendingPathComponent("target")
        try Data("deadbeef".utf8).write(to: target)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: target.path)
        let link = dir.appendingPathComponent("link")
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: target)
        XCTAssertEqual(TokenFile.read(at: link), .problem(.symlink))
        // The target itself is still fine — only the link is refused.
        XCTAssertEqual(TokenFile.read(at: target), .ok("deadbeef"))
    }

    func testFifoIsRefusedWithoutOpeningIt() throws {
        let dir = try tempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let path = dir.appendingPathComponent("fifo")
        XCTAssertEqual(mkfifo(path.path, 0o600), 0, "mkfifo failed")
        XCTAssertEqual(TokenFile.read(at: path), .problem(.notRegularFile))
    }

    func testDirectoryIsRefused() throws {
        let dir = try tempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        XCTAssertEqual(TokenFile.read(at: dir), .problem(.notRegularFile))
    }

    func testOversizedFileIsRefused() throws {
        let dir = try tempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let path = dir.appendingPathComponent("api.token")
        try Data(repeating: 0x61, count: TokenFile.maxBytes + 1).write(to: path)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: path.path)
        XCTAssertEqual(TokenFile.read(at: path), .problem(.tooLarge))
    }

    func testNonAsciiTokenIsRefused() throws {
        let dir = try tempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let path = dir.appendingPathComponent("api.token")
        try Data("tökén".utf8).write(to: path)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: path.path)
        XCTAssertEqual(TokenFile.read(at: path), .problem(.invalidEncoding))
    }

    func testEmptyFileIsRefused() throws {
        let dir = try tempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let path = dir.appendingPathComponent("api.token")
        try Data().write(to: path)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: path.path)
        XCTAssertEqual(TokenFile.read(at: path), .problem(.invalidEncoding))
    }

    // MARK: fd guard, ownership, directory, race

    func testTokenLongerThanTheCapIsRefused() throws {
        let dir = try tempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let path = dir.appendingPathComponent("api.token")
        let maxToken = String(repeating: "a", count: TokenFile.maxTokenChars)
        try Data(maxToken.utf8).write(to: path)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: path.path)
        XCTAssertEqual(TokenFile.read(at: path), .ok(maxToken), "the cap itself is accepted")

        let tooLong = String(repeating: "b", count: TokenFile.maxTokenChars + 1)
        try Data(tooLong.utf8).write(to: path)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: path.path)
        XCTAssertEqual(TokenFile.read(at: path), .problem(.invalidEncoding), "one over the cap is refused")
    }

    func testGroupOrWorldBitsAreRefused() throws {
        let dir = try tempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let path = dir.appendingPathComponent("api.token")
        try Data("deadbeef".utf8).write(to: path)
        for mode in [0o640, 0o604, 0o660, 0o700] {
            try FileManager.default.setAttributes([.posixPermissions: mode], ofItemAtPath: path.path)
            guard case .problem(.permissions) = TokenFile.read(at: path) else {
                return XCTFail("mode \(String(mode, radix: 8)) must be refused")
            }
        }
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: path.path)
        XCTAssertEqual(TokenFile.read(at: path), .ok("deadbeef"))
    }

    /// Root is required to create a file owned by another uid, so the file
    /// ownership refusal is exercised through the injectable `expectedOwner`
    /// seam: the file and the directory are owned by the *test user*, and the
    /// reader is told the file should belong to a different owner.
    func testAnotherOwnerIsRefusedViaTheOwnershipSeam() throws {
        let dir = try tempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let path = dir.appendingPathComponent("api.token")
        try Data("deadbeef".utf8).write(to: path)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: path.path)
        XCTAssertEqual(TokenFile.read(at: path, expectedOwner: getuid()), .ok("deadbeef"))
        XCTAssertEqual(TokenFile.read(at: path, expectedOwner: getuid() &+ 1), .problem(.wrongOwner))
    }

    /// The home-directory ownership check has its own seam (root is needed to
    /// create a real other-owned directory).
    func testOtherOwnerHomeIsRefusedViaTheDirectorySeam() throws {
        let dir = try tempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let path = dir.appendingPathComponent("api.token")
        XCTAssertNil(TokenFile.directoryProblem(for: path, expectedOwner: getuid()))
        XCTAssertEqual(
            TokenFile.directoryProblem(for: path, expectedOwner: getuid() &+ 1),
            .wrongOwner,
            "the Auxesis home must be owned by the user"
        )
    }

    func testGroupWritableHomeDirectoryIsRefused() throws {
        let dir = try tempDirectory()
        defer {
            try? FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: dir.path)
            try? FileManager.default.removeItem(at: dir)
        }
        let path = dir.appendingPathComponent("api.token")
        try Data("deadbeef".utf8).write(to: path)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: path.path)
        for mode in [0o770, 0o775, 0o707, 0o777] {
            try FileManager.default.setAttributes([.posixPermissions: mode], ofItemAtPath: dir.path)
            XCTAssertEqual(
                TokenFile.read(at: path),
                .problem(.unsafeDirectory),
                "home mode \(String(mode, radix: 8)) must be refused"
            )
        }
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: dir.path)
        XCTAssertEqual(TokenFile.read(at: path), .ok("deadbeef"))
    }

    func testSymlinkedHomeDirectoryIsRefused() throws {
        let parent = try tempDirectory()
        defer { try? FileManager.default.removeItem(at: parent) }
        let real = parent.appendingPathComponent("real", isDirectory: true)
        try FileManager.default.createDirectory(at: real, withIntermediateDirectories: true)
        let link = parent.appendingPathComponent("home", isDirectory: true)
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: real)
        let path = link.appendingPathComponent("api.token")
        try Data("deadbeef".utf8).write(to: path)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: path.path)
        XCTAssertEqual(TokenFile.read(at: path), .problem(.unsafeDirectory))
    }

    /// The original lstat-then-open TOCTOU: while a writer swaps a symlink (to
    /// a file containing `target-token`) with the honest regular file, a reader
    /// following the link would eventually read the target. With
    /// `open(O_NOFOLLOW)` + `fstat` the target token can never appear.
    func testSymlinkSwapRaceNeverReadsThroughTheLink() throws {
        let dir = try tempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let target = dir.appendingPathComponent("target")
        try Data("target-token".utf8).write(to: target)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: target.path)

        let path = dir.appendingPathComponent("api.token")
        let staging = dir.appendingPathComponent("staging")
        try Data("honest-token".utf8).write(to: staging)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: staging.path)
        _ = rename(staging.path, path.path)

        let stop = AtomicFlag()
        let writer = Thread {
            var flip = false
            while !stop.isSet {
                if flip {
                    try? FileManager.default.removeItem(at: staging)
                    try? FileManager.default.createSymbolicLink(at: staging, withDestinationURL: target)
                    _ = rename(staging.path, path.path)
                } else {
                    try? FileManager.default.removeItem(at: staging)
                    try? Data("honest-token".utf8).write(to: staging)
                    try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: staging.path)
                    _ = rename(staging.path, path.path)
                }
                flip.toggle()
            }
        }
        writer.start()
        defer {
            stop.set()
            let deadline = Date().addingTimeInterval(3)
            while writer.isExecuting, Date() < deadline { usleep(1_000) }
        }

        var honestReads = 0
        let deadline = Date().addingTimeInterval(0.5)
        while Date() < deadline {
            switch TokenFile.read(at: path) {
            case .ok(let token):
                XCTAssertNotEqual(token, "target-token", "the token must never be read through the symlink")
                if token == "honest-token" { honestReads += 1 }
            case .problem(.symlink), .problem(.missing):
                break // the swap was caught mid-flight: fine
            case .problem(let other):
                XCTFail("unexpected problem during the race: \(other)")
            }
        }
        XCTAssertGreaterThan(honestReads, 0, "the honest file stays readable during the race")
    }

    /// A FIFO at the path must be refused without the open blocking the caller:
    /// `O_NONBLOCK` lets the open return, and `fstat` on the fd proves the kind.
    func testFifoRaceIsRefusedOnTheDescriptorNotThePath() throws {
        let dir = try tempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let path = dir.appendingPathComponent("api.token")
        XCTAssertEqual(mkfifo(path.path, 0o600), 0, "mkfifo failed")
        let start = Date()
        XCTAssertEqual(TokenFile.read(at: path), .problem(.notRegularFile))
        XCTAssertLessThan(Date().timeIntervalSince(start), 1, "the read must not block on the FIFO")
    }
}

/// Tiny lock-protected flag for the race test.
final class AtomicFlag: @unchecked Sendable {
    private let lock = NSLock()
    private var value = false

    var isSet: Bool { lock.withLock { value } }
    func set() { lock.withLock { value = true } }
}
