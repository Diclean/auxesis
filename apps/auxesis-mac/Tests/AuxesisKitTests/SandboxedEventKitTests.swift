import XCTest
@testable import AuxesisKit

/// A sandbox run must never read the owner's real calendar, even when the
/// bundle id already holds Calendar access.
@objcMembers @MainActor final class SandboxedEventKitTests: XCTestCase {
    func testSandboxedKitNeverAuthorizesNorReturnsData() async throws {
        let kit = SandboxedAppleEventKit()
        XCTAssertEqual(kit.access, .denied)
        let asked = try await kit.requestAccessAndRead()
        XCTAssertFalse(asked.authorized)
        XCTAssertTrue(asked.events.isEmpty && asked.reminders.isEmpty)
        let read = try await kit.readIfAuthorized()
        XCTAssertFalse(read.authorized)
    }

    func testSandboxBridgeRefusesCalendarWrites() async {
        // A HOME-only sandbox (AUXESIS_SANDBOX unset) refuses every write.
        let tempHome = FileManager.default.temporaryDirectory.path
        let refusing = bridgeEventWriter(environment: ["HOME": tempHome])
        XCTAssertTrue(refusing is SandboxedEventWriter)
        do {
            _ = try await refusing.createEvent(
                calendar: nil, title: "Fictional", start: "2026-10-16T09:00:00Z",
                end: "2026-10-16T10:00:00Z", location: nil, notes: nil, url: nil)
            XCTFail("a sandbox bridge write must be refused")
        } catch {}
        do {
            _ = try await refusing.updateEvent(
                eventId: "x", calendar: nil, title: nil, start: nil, end: nil,
                location: nil, notes: nil, url: nil, expected: nil)
            XCTFail("a sandbox bridge update must be refused")
        } catch {}
        // The owner path: HOME is the OS user's home, no sandbox flag.
        guard let ownerHome = EndpointResolver.osHomeDirectory()?.path else {
            return XCTFail("no OS user home")
        }
        XCTAssertFalse(bridgeEventWriter(environment: ["HOME": ownerHome]) is SandboxedEventWriter)
    }

    /// A sandbox run with the flag records its calendar writes under the
    /// throwaway home, so an approved event can be proved. It never touches
    /// EventKit: the owner's calendars are never read nor written.
    func testSandboxBridgeRecordsItsWritesUnderTheThrowawayHome() async throws {
        let home = FileManager.default.temporaryDirectory
            .appendingPathComponent("sandbox-calendar-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: home) }
        try FileManager.default.createDirectory(at: home, withIntermediateDirectories: true)
        let writer = bridgeEventWriter(environment: ["AUXESIS_SANDBOX": "1", "AUXESIS_HOME": home.path])
        XCTAssertTrue(writer is SandboxRecordingEventWriter)
        let created = try await writer.createEvent(
            calendar: nil, title: "Fictional sync tomorrow",
            start: "2026-10-31T10:00:00+02:00", end: "2026-10-31T11:00:00+02:00",
            location: nil, notes: nil, url: nil)
        XCTAssertFalse(created.eventId.isEmpty)
        let text = try String(
            contentsOf: home.appendingPathComponent("sandbox-calendar.jsonl"), encoding: .utf8)
        for expected in ["Fictional sync tomorrow", "2026-10-31T10:00:00+02:00", created.eventId] {
            XCTAssertTrue(text.contains(expected), text)
        }
        // A move keeps the event's id: the record still holds one event.
        let moved = try await writer.updateEvent(
            eventId: created.eventId, calendar: nil, title: nil, start: "2026-10-31T15:00:00+02:00",
            end: "2026-10-31T16:00:00+02:00", location: nil, notes: nil, url: nil, expected: nil)
        XCTAssertEqual(moved.eventId, created.eventId)
        // Without the flag the recording writer is never chosen: the owner's
        // app writes the owner's calendars, not a file.
        XCTAssertFalse(bridgeEventWriter(environment: ["HOME": home.path]) is SandboxRecordingEventWriter)
    }

    // MARK: - The record file is never followed and never grows without a bound

    /// A symlink at the record path must never be followed: the write is
    /// refused and the file the link points at keeps its bytes. A link that
    /// appends would write into a file the sandbox does not own.
    func testSandboxRecordNeverFollowsASymlink() async throws {
        let home = try sandboxHome("symlink")
        defer { try? FileManager.default.removeItem(at: home) }
        let target = FileManager.default.temporaryDirectory
            .appendingPathComponent("sandbox-record-target-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: target) }
        let owner = Data("the owner's own bytes\n".utf8)
        try owner.write(to: target)
        try FileManager.default.createSymbolicLink(
            at: home.appendingPathComponent("sandbox-calendar.jsonl"),
            withDestinationURL: target)
        let writer = bridgeEventWriter(environment: ["AUXESIS_SANDBOX": "1", "AUXESIS_HOME": home.path])
        do {
            _ = try await writer.createEvent(
                calendar: nil, title: "Fictional", start: "2026-10-31T10:00:00+02:00",
                end: "2026-10-31T11:00:00+02:00", location: nil, notes: nil, url: nil)
            XCTFail("a symlinked record must be refused, never followed")
        } catch {}
        XCTAssertEqual(try Data(contentsOf: target), owner)
    }

    /// A directory at the record path is not a record file: the write fails
    /// and no event id comes back.
    func testSandboxRecordRefusesADirectory() async throws {
        let home = try sandboxHome("directory")
        defer { try? FileManager.default.removeItem(at: home) }
        let record = home.appendingPathComponent("sandbox-calendar.jsonl")
        try FileManager.default.createDirectory(at: record, withIntermediateDirectories: true)
        let writer = bridgeEventWriter(environment: ["AUXESIS_SANDBOX": "1", "AUXESIS_HOME": home.path])
        do {
            _ = try await writer.createEvent(
                calendar: nil, title: "Fictional", start: "2026-10-31T10:00:00+02:00",
                end: "2026-10-31T11:00:00+02:00", location: nil, notes: nil, url: nil)
            XCTFail("a directory at the record path must be refused")
        } catch {}
        var isDirectory: ObjCBool = false
        XCTAssertTrue(FileManager.default.fileExists(atPath: record.path, isDirectory: &isDirectory))
        XCTAssertTrue(isDirectory.boolValue)
    }

    /// A record at the cap is refused: the file never grows without a bound
    /// and the bytes already there are untouched.
    func testSandboxRecordRefusesAFileAtTheCap() async throws {
        let home = try sandboxHome("cap")
        defer { try? FileManager.default.removeItem(at: home) }
        let record = home.appendingPathComponent("sandbox-calendar.jsonl")
        let cap = SandboxRecordingEventWriter.maxRecordBytes
        try Data(repeating: 0x41, count: cap).write(to: record)
        let writer = bridgeEventWriter(environment: ["AUXESIS_SANDBOX": "1", "AUXESIS_HOME": home.path])
        do {
            _ = try await writer.createEvent(
                calendar: nil, title: "Fictional", start: "2026-10-31T10:00:00+02:00",
                end: "2026-10-31T11:00:00+02:00", location: nil, notes: nil, url: nil)
            XCTFail("a record at the cap must be refused")
        } catch {}
        XCTAssertEqual(try Data(contentsOf: record).count, cap)
    }

    /// The normal path still appends the line, and the record file stays
    /// private to its owner (0600).
    func testSandboxRecordAppendsAndKeepsTheFilePrivate() async throws {
        let home = try sandboxHome("append")
        defer { try? FileManager.default.removeItem(at: home) }
        let writer = bridgeEventWriter(environment: ["AUXESIS_SANDBOX": "1", "AUXESIS_HOME": home.path])
        let created = try await writer.createEvent(
            calendar: nil, title: "Fictional sync tomorrow",
            start: "2026-10-31T10:00:00+02:00", end: "2026-10-31T11:00:00+02:00",
            location: nil, notes: nil, url: nil)
        XCTAssertFalse(created.eventId.isEmpty)
        let record = home.appendingPathComponent("sandbox-calendar.jsonl")
        let text = try String(contentsOf: record, encoding: .utf8)
        XCTAssertTrue(text.contains(created.eventId), text)
        XCTAssertTrue(text.contains("Fictional sync tomorrow"), text)
        let attributes = try FileManager.default.attributesOfItem(atPath: record.path)
        let permissions = (attributes[.posixPermissions] as? NSNumber)?.intValue
        XCTAssertEqual(permissions, 0o600)
    }

    /// The parent of the record must be the validated sandbox home itself: a
    /// home that is a symlink is not it, and the record is never written
    /// through the link.
    func testSandboxRecordRefusesASymlinkedHome() async throws {
        let base = try sandboxHome("symlinked-home")
        defer { try? FileManager.default.removeItem(at: base) }
        let real = base.appendingPathComponent("real", isDirectory: true)
        try FileManager.default.createDirectory(at: real, withIntermediateDirectories: true)
        let link = base.appendingPathComponent("link", isDirectory: true)
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: real)
        let writer = bridgeEventWriter(environment: ["AUXESIS_SANDBOX": "1", "AUXESIS_HOME": link.path])
        do {
            _ = try await writer.createEvent(
                calendar: nil, title: "Fictional", start: "2026-10-31T10:00:00+02:00",
                end: "2026-10-31T11:00:00+02:00", location: nil, notes: nil, url: nil)
            XCTFail("a symlinked home must be refused")
        } catch {}
        XCTAssertTrue(try FileManager.default.contentsOfDirectory(atPath: real.path).isEmpty)
    }

    /// The home is resolved once, by opening it: a home that is swapped for
    /// a symlink after the writer exists cannot redirect the record. The next
    /// record fails — the open refuses the link with ELOOP — and the
    /// directory the link points at keeps its own bytes: the record never
    /// lands in the link target, and the original home keeps the first
    /// record only.
    func testSandboxRecordNeverFollowsAHomeSwappedAfterTheWriterExists() async throws {
        let base = try sandboxHome("swapped-home")
        defer { try? FileManager.default.removeItem(at: base) }
        let home = base.appendingPathComponent("home", isDirectory: true)
        try FileManager.default.createDirectory(at: home, withIntermediateDirectories: true)
        let writer = bridgeEventWriter(environment: ["AUXESIS_SANDBOX": "1", "AUXESIS_HOME": home.path])

        // The record lands in the home itself.
        let first = try await writer.createEvent(
            calendar: nil, title: "Fictional", start: "2026-10-31T10:00:00+02:00",
            end: "2026-10-31T11:00:00+02:00", location: nil, notes: nil, url: nil)
        XCTAssertFalse(first.eventId.isEmpty)
        let record = home.appendingPathComponent("sandbox-calendar.jsonl")
        XCTAssertTrue(try String(contentsOf: record, encoding: .utf8).contains(first.eventId))

        // The home is replaced by a symlink to a directory the sandbox owns
        // nothing of; the original home moves aside, so where a record lands
        // is visible.
        let elsewhere = base.appendingPathComponent("elsewhere", isDirectory: true)
        try FileManager.default.createDirectory(at: elsewhere, withIntermediateDirectories: true)
        let original = base.appendingPathComponent("original-home", isDirectory: true)
        try FileManager.default.moveItem(at: home, to: original)
        try FileManager.default.createSymbolicLink(at: home, withDestinationURL: elsewhere)

        // The next record cannot follow the link: the home is resolved again
        // on every record and a home that has become a symlink is refused
        // (ELOOP), so the write fails. The other safe outcome — landing in
        // the original home — is not what this writer does; the link target
        // is never written to either way.
        do {
            _ = try await writer.createEvent(
                calendar: nil, title: "Second", start: "2026-10-31T12:00:00+02:00",
                end: "2026-10-31T13:00:00+02:00", location: nil, notes: nil, url: nil)
            XCTFail("a home swapped for a symlink must be refused, never followed")
        } catch {}

        // The link target keeps its own bytes, and the original home keeps
        // the first record only.
        XCTAssertTrue(try FileManager.default.contentsOfDirectory(atPath: elsewhere.path).isEmpty)
        let kept = try String(
            contentsOf: original.appendingPathComponent("sandbox-calendar.jsonl"), encoding: .utf8)
        XCTAssertTrue(kept.contains(first.eventId), kept)
        XCTAssertFalse(kept.contains("Second"), kept)
    }

    /// A home that traverses (`..`) is not a sandbox home: the record must not
    /// land outside the throwaway home the run deletes.
    func testSandboxRecordRefusesATraversingHome() async throws {
        let base = try sandboxHome("traversal")
        defer { try? FileManager.default.removeItem(at: base) }
        let sub = base.appendingPathComponent("sub", isDirectory: true)
        try FileManager.default.createDirectory(at: sub, withIntermediateDirectories: true)
        let outside = base.appendingPathComponent("outside", isDirectory: true)
        try FileManager.default.createDirectory(at: outside, withIntermediateDirectories: true)
        let traversing = sub.appendingPathComponent("..").appendingPathComponent("outside")
        let writer = bridgeEventWriter(environment: ["AUXESIS_SANDBOX": "1", "AUXESIS_HOME": traversing.path])
        do {
            _ = try await writer.createEvent(
                calendar: nil, title: "Fictional", start: "2026-10-31T10:00:00+02:00",
                end: "2026-10-31T11:00:00+02:00", location: nil, notes: nil, url: nil)
            XCTFail("a traversing home must be refused")
        } catch {}
        XCTAssertTrue(try FileManager.default.contentsOfDirectory(atPath: outside.path).isEmpty)
    }

    /// A throwaway sandbox home, created, with the record file in it.
    private func sandboxHome(_ label: String) throws -> URL {
        let home = FileManager.default.temporaryDirectory
            .appendingPathComponent("sandbox-record-\(label)-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: home, withIntermediateDirectories: true)
        return home
    }
}
