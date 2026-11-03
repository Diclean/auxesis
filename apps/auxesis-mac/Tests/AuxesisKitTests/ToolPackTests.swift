import XCTest
@testable import AuxesisKit
import Darwin

@objcMembers @MainActor final class ToolPackTests: XCTestCase {
    private enum SimulatedFailure: Error { case put, fetch }

    private var mail: ToolPack { ToolPacks.presets.first { $0.id == "mail" }! }
    private var agenda: ToolPack { ToolPacks.presets.first { $0.id == "agenda" }! }

    private func temporaryPersistence() -> (URL, PackAssignmentPersistence) {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("tool-pack-tests-\(UUID().uuidString)", isDirectory: true)
        return (directory, PackAssignmentPersistence(directory: directory))
    }

    private func rawRecord(
        agentID: String,
        version: Int = 1,
        records: [String: Any] = [:],
        removals: [String: Any] = [:]
    ) throws -> Data {
        try JSONSerialization.data(withJSONObject: [
            "version": version,
            "agentID": agentID,
            "recordsByPackID": records,
            "pendingRemovalsByPackID": removals,
        ])
    }

    private func writeRaw(_ data: Data, agent: String, persistence: PackAssignmentPersistence) throws {
        try FileManager.default.createDirectory(
            at: persistence.recordURL(agent: agent).deletingLastPathComponent(),
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: NSNumber(value: 0o700)]
        )
        try data.write(to: persistence.recordURL(agent: agent))
    }

    private func mode(at url: URL) -> Int {
        var info = stat()
        guard lstat(url.path, &info) == 0 else { return -1 }
        return Int(info.st_mode & 0o777)
    }

    func testAddingPackDeduplicatesInFirstSeenOrderLikeTheAPI() {
        let pack = ToolPacks.presets.first { $0.id == "recherche-web" }!
        let before = ["write_file", "read_file", "write_file"]
        let assigned = ToolPacks.union(current: before, pack: pack, available: ["http_fetch"])
        let assignment = PackAssignment(packID: pack.id, addedTools: assigned.filter { !before.contains($0) })

        XCTAssertEqual(assigned, ["write_file", "read_file", "http_fetch"])
        XCTAssertEqual(assignment.addedTools, ["http_fetch"])
    }

    func testRemovingPackPreservesHandTunedToolAddedAfterAssignment() {
        var journal = PackSetAssignment(addedToolsByPack: ["recherche-web": ["http_fetch"]])
        let live = ["http_fetch", "read_file", "write_file"]

        let desired = journal.prepareRemoval(packID: "recherche-web", liveTools: live)

        XCTAssertEqual(desired, ["read_file", "write_file"])
        XCTAssertEqual(journal.pendingRemovalsByPackID["recherche-web"]?.intendedRemoved, ["http_fetch"])
        journal.reconcilePending(with: ["read_file", "write_file"])
        XCTAssertTrue(journal.isEmpty)
    }

    func testRemovingOnePackKeepsToolsNeededByAnotherPack() {
        var journal = PackSetAssignment(addedToolsByPack: [mail.id: ["mail_list"], agenda.id: ["calendar_list"]])
        let live = ["mail_list", "calendar_list"]

        let desired = journal.prepareRemoval(packID: mail.id, liveTools: live)

        XCTAssertEqual(desired, ["calendar_list"])
        XCTAssertEqual(journal.recordsByPackID[agenda.id]?.intendedAdded, ["calendar_list"])
    }

    func testLostPutResponseReconcilesAsSuccessWhenLiveListMatches() {
        XCTAssertTrue(ToolPacks.reconciled(expected: ["read_file", "http_fetch"], live: ["read_file", "http_fetch"]))
    }

    func testLostPutResponseReconcilesAsFailureWhenLiveListDiffers() {
        XCTAssertFalse(ToolPacks.reconciled(expected: ["read_file", "http_fetch"], live: ["read_file"]))
    }

    func testReconcileTreatsAPIFirstSeenOrderDeduplicationAsSuccess() {
        XCTAssertTrue(ToolPacks.reconciled(expected: ["read_file", "http_fetch", "read_file"], live: ["read_file", "http_fetch"]))
    }

    func testDiffTextNeverShowsToolIdentifiers() {
        let identifiers = ["mail_list", "mail_search", "mail_read", "mail_draft", "mail_send", "calendar_list", "calendar_create_event", "http_fetch", "shell_exec"]
        let text = ToolPacks.diffText(previous: [], current: identifiers, .fr)

        for identifier in identifiers { XCTAssertFalse(text.contains(identifier), "diff leaked \(identifier)") }
        XCTAssertTrue(text.contains("consulter tes emails"))
        XCTAssertTrue(text.contains("un outil"))
    }

    func testExplicitDenyStillWinsAfterPackAddsToolToAllowlist() {
        let pack = ToolPacks.presets.first { $0.id == "recherche-web" }!
        let allowlist = ToolPacks.union(current: [], pack: pack, available: ["http_fetch"])

        XCTAssertFalse(ToolPacks.canCall(tool: "http_fetch", allowlist: allowlist, deniedTools: ["http_fetch"]))
    }

    func testNilToolsUpdateEncodesNullSoServerClearsAllowlist() throws {
        let data = try JSONEncoder().encode(AgentToolsUpdate(tools: nil))
        let object = try JSONSerialization.jsonObject(with: data) as? [String: Any]

        XCTAssertTrue(object?["tools"] is NSNull)
    }

    func testPartialAssignmentFailureRetainsAppliedToolsForLaterRemoval() {
        var journal = PackSetAssignment()
        let registry = Set(mail.tools)
        let before = ["shell_exec", "hand_tuned"]

        let desired = journal.prepareAssignment(pack: mail, liveTools: before, available: registry)
        XCTAssertEqual(desired, before + mail.tools)
        XCTAssertEqual(journal.recordsByPackID[mail.id]?.state, .pending)
        let partiallyApplied = before + Array(mail.tools.prefix(2))
        journal.reconcilePending(with: partiallyApplied)
        XCTAssertEqual(journal.recordsByPackID[mail.id]?.state, .applied)
        XCTAssertEqual(journal.ownedTools(packID: mail.id, liveTools: partiallyApplied), Array(mail.tools.prefix(2)))

        let retry = journal.prepareAssignment(pack: mail, liveTools: partiallyApplied, available: registry)
        XCTAssertEqual(retry, before + mail.tools)
        let fullyApplied = before + mail.tools
        journal.markAssignmentApplied(packID: mail.id)
        let removal = journal.prepareRemoval(packID: mail.id, liveTools: fullyApplied)

        XCTAssertEqual(removal, before)
        journal.reconcilePending(with: before)
        XCTAssertTrue(journal.isEmpty)
    }

    func testRepeatedPartialAssignmentFailuresAccumulateOwnership() {
        var journal = PackSetAssignment()
        let registry = Set(mail.tools)
        let before = ["shell_exec"]

        _ = journal.prepareAssignment(pack: mail, liveTools: before, available: registry)
        let firstPartial = before + Array(mail.tools.prefix(2))
        journal.reconcilePending(with: firstPartial)

        _ = journal.prepareAssignment(pack: mail, liveTools: firstPartial, available: registry)
        let secondPartial = firstPartial + [mail.tools[2]]
        journal.reconcilePending(with: secondPartial)

        XCTAssertEqual(journal.recordsByPackID[mail.id]?.intendedAdded, mail.tools)
        XCTAssertEqual(journal.ownedTools(packID: mail.id, liveTools: secondPartial), Array(mail.tools.prefix(3)))
    }

    func testPartialRemovalFailureRetainsRemainingOwnershipForRetry() {
        var journal = PackSetAssignment(addedToolsByPack: [mail.id: mail.tools])
        let before = ["shell_exec", "hand_tuned"]
        let live = before + mail.tools

        let firstRemoval = journal.prepareRemoval(packID: mail.id, liveTools: live)
        let partiallyRemoved = before + Array(mail.tools.suffix(3))
        journal.reconcilePending(with: partiallyRemoved)
        XCTAssertNotNil(journal.pendingRemovalsByPackID[mail.id])
        XCTAssertEqual(journal.ownedTools(packID: mail.id, liveTools: partiallyRemoved), Array(mail.tools.suffix(3)))

        let retryRemoval = journal.prepareRemoval(packID: mail.id, liveTools: partiallyRemoved)
        XCTAssertEqual(firstRemoval, before)
        XCTAssertEqual(retryRemoval, before)
        journal.reconcilePending(with: before)
        XCTAssertTrue(journal.isEmpty)
    }

    func testRetryUnionsPreviouslyOwnedToolsWithNewlyIntroducedTools() {
        let existing = Array(mail.tools.prefix(2))
        let live = ["shell_exec"] + existing
        var journal = PackSetAssignment(addedToolsByPack: [mail.id: existing])

        _ = journal.prepareAssignment(pack: mail, liveTools: live, available: Set(mail.tools))

        XCTAssertEqual(journal.recordsByPackID[mail.id]?.intendedAdded, mail.tools)
    }

    func testRelaunchAfterPutAndRefetchFailureStillRemovesPartiallyAppliedTools() throws {
        let (directory, firstLaunch) = temporaryPersistence()
        defer { try? FileManager.default.removeItem(at: directory) }
        let before = ["shell_exec", "hand_tuned"]
        let registry = Set(mail.tools)
        var live = before

        // The journal is written before PUT; the daemon applies two tools,
        // then the PUT and the immediate reconcile read both fail.
        var pending = firstLaunch.load(agent: "Builder")
        let desired = pending.prepareAssignment(pack: mail, liveTools: live, available: registry)
        try firstLaunch.save(pending, agent: "Builder")
        XCTAssertEqual(firstLaunch.load(agent: "Builder").recordsByPackID[mail.id]?.state, .pending)
        do {
            live += Array(mail.tools.prefix(2))
            throw SimulatedFailure.put
        } catch {
            XCTAssertNotEqual(desired, live)
            XCTAssertEqual(firstLaunch.load(agent: "Builder").recordsByPackID[mail.id]?.state, .pending)
        }
        do {
            throw SimulatedFailure.fetch
        } catch {
            XCTAssertEqual(firstLaunch.load(agent: "Builder").recordsByPackID[mail.id]?.intendedAdded, mail.tools)
        }

        // A new process has only the durable record and the next live fetch.
        let relaunched = PackAssignmentPersistence(directory: directory)
        var recovered = relaunched.load(agent: "Builder")
        XCTAssertEqual(recovered.recordsByPackID[mail.id]?.intendedAdded, mail.tools)
        recovered.reconcilePending(with: live)
        try relaunched.save(recovered, agent: "Builder")
        XCTAssertEqual(recovered.ownedTools(packID: mail.id, liveTools: live), Array(mail.tools.prefix(2)))

        // Retry the assignment, then remove it through a durable removal record.
        let retry = recovered.prepareAssignment(pack: mail, liveTools: live, available: registry)
        try relaunched.save(recovered, agent: "Builder")
        live = retry
        recovered.markAssignmentApplied(packID: mail.id)
        try relaunched.save(recovered, agent: "Builder")
        let removal = recovered.prepareRemoval(packID: mail.id, liveTools: live)!
        try relaunched.save(recovered, agent: "Builder")
        live = removal
        recovered.reconcilePending(with: live)
        try relaunched.save(recovered, agent: "Builder")

        XCTAssertEqual(live, before)
        XCTAssertTrue(relaunched.load(agent: "Builder").isEmpty)
    }

    func testAssignAPartialThenAssignBThenRemoveA() {
        var journal = PackSetAssignment()
        let before = ["shell_exec", "hand_tuned"]
        _ = journal.prepareAssignment(pack: mail, liveTools: before, available: Set(mail.tools))
        var live = before + Array(mail.tools.prefix(2))
        journal.reconcilePending(with: live)

        _ = journal.prepareAssignment(pack: agenda, liveTools: live, available: Set(agenda.tools))
        live += agenda.tools
        journal.markAssignmentApplied(packID: agenda.id)

        let afterRemovingA = journal.prepareRemoval(packID: mail.id, liveTools: live)
        XCTAssertEqual(afterRemovingA, before + agenda.tools)
        XCTAssertEqual(journal.recordsByPackID[agenda.id]?.state, .applied)
        XCTAssertEqual(journal.pendingRemovalsByPackID[mail.id]?.intendedRemoved, Array(mail.tools.prefix(2)))
    }

    func testFailedRemovalSurvivesRelaunchAndRetry() throws {
        let (directory, firstLaunch) = temporaryPersistence()
        defer { try? FileManager.default.removeItem(at: directory) }
        let before = ["shell_exec", "hand_tuned"]
        var journal = PackSetAssignment(addedToolsByPack: [mail.id: mail.tools])
        var live = before + mail.tools

        let desired = journal.prepareRemoval(packID: mail.id, liveTools: live)!
        try firstLaunch.save(journal, agent: "Builder")
        do {
            live = before + Array(mail.tools.suffix(3))
            throw SimulatedFailure.put
        } catch {
            XCTAssertEqual(firstLaunch.load(agent: "Builder").pendingRemovalsByPackID[mail.id]?.intendedRemoved, mail.tools)
        }
        do {
            throw SimulatedFailure.fetch
        } catch {
            XCTAssertEqual(firstLaunch.load(agent: "Builder").recordsByPackID[mail.id]?.state, .applied)
        }

        let relaunched = PackAssignmentPersistence(directory: directory)
        var recovered = relaunched.load(agent: "Builder")
        recovered.reconcilePending(with: live)
        XCTAssertEqual(recovered.pendingRemovalsByPackID[mail.id]?.intendedRemoved, mail.tools)
        try relaunched.save(recovered, agent: "Builder")

        let retry = recovered.prepareRemoval(packID: mail.id, liveTools: live)!
        XCTAssertEqual(desired, before)
        XCTAssertEqual(retry, before)
        try relaunched.save(recovered, agent: "Builder")
        live = retry
        recovered.reconcilePending(with: live)
        try relaunched.save(recovered, agent: "Builder")

        XCTAssertEqual(live, before)
        XCTAssertTrue(relaunched.load(agent: "Builder").isEmpty)
    }

    func testCorruptedOrMissingRecordFallsBackWithoutClaimingPreExistingTools() throws {
        let (directory, persistence) = temporaryPersistence()
        defer { try? FileManager.default.removeItem(at: directory) }
        XCTAssertTrue(persistence.load(agent: "Missing").isEmpty)

        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let suite = "tool-pack-corrupt-\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suite)!
        defer { defaults.removePersistentDomain(forName: suite) }
        let legacyKey = "auxesis.pack-assignment.Corrupt"
        let oldData = try JSONSerialization.data(withJSONObject: ["addedToolsByPack": [mail.id: mail.tools]])
        defaults.set(oldData, forKey: legacyKey)
        try Data("not valid journal json".utf8).write(to: persistence.recordURL(agent: "Corrupt"))
        let withLegacyFallback = PackAssignmentPersistence(directory: directory, legacyDefaults: defaults)
        var recovered = withLegacyFallback.load(agent: "Corrupt")
        XCTAssertTrue(recovered.isEmpty)
        XCTAssertNotNil(defaults.data(forKey: legacyKey))

        let preExisting = ["shell_exec", "hand_tuned"] + mail.tools
        _ = recovered.prepareAssignment(pack: mail, liveTools: preExisting, available: Set(mail.tools))
        XCTAssertEqual(recovered.recordsByPackID[mail.id]?.preExistingTools, preExisting)
        XCTAssertEqual(recovered.recordsByPackID[mail.id]?.intendedAdded, [])
        XCTAssertEqual(recovered.ownedTools(packID: mail.id, liveTools: preExisting), [])
    }

    func testLegacyUserDefaultsOwnershipMigratesIntoTheAtomicPerAgentFile() throws {
        let (directory, _) = temporaryPersistence()
        defer { try? FileManager.default.removeItem(at: directory) }
        let suite = "tool-pack-migration-\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suite)!
        defer { defaults.removePersistentDomain(forName: suite) }
        let legacyKey = "auxesis.pack-assignment.Builder"
        let oldData = try JSONSerialization.data(withJSONObject: ["addedToolsByPack": [mail.id: mail.tools]])
        defaults.set(oldData, forKey: legacyKey)
        let persistence = PackAssignmentPersistence(directory: directory, legacyDefaults: defaults)

        let migrated = persistence.load(agent: "Builder")

        XCTAssertEqual(migrated.recordsByPackID[mail.id]?.intendedAdded, mail.tools)
        XCTAssertTrue(FileManager.default.fileExists(atPath: persistence.recordURL(agent: "Builder").path))
        XCTAssertNil(defaults.data(forKey: legacyKey))
    }

    func testConcurrentDoubleTapStartsOnlyOneOperationPerAgent() {
        let persistence = PackAssignmentPersistence(directory: FileManager.default.temporaryDirectory)
        let resultLock = NSLock()
        var results: [Bool] = []

        DispatchQueue.concurrentPerform(iterations: 2) { _ in
            let started = persistence.beginOperation(agent: "Builder")
            resultLock.lock()
            results.append(started)
            resultLock.unlock()
        }

        XCTAssertEqual(results.filter { $0 }.count, 1)
        persistence.endOperation(agent: "Builder")
        XCTAssertTrue(persistence.beginOperation(agent: "Builder"))
        persistence.endOperation(agent: "Builder")
    }

    func testTwentyFourToolCapRemainsAnInclusiveLimit() {
        let pack = ToolPack(id: "large", titleKey: .packMailTitle, descriptionKey: .packMailDescription, tools: ["new_tool"], requires_apps: [])

        XCTAssertTrue(ToolPacks.fitsAgentLimit(current: (0..<23).map { "existing_\($0)" }, pack: pack, available: ["new_tool"]))
        XCTAssertFalse(ToolPacks.fitsAgentLimit(current: (0..<24).map { "existing_\($0)" }, pack: pack, available: ["new_tool"]))
    }

    func testJournalDirectoryAndFilesArePrivateAndExistingModesAreTightened() throws {
        let (directory, persistence) = temporaryPersistence()
        defer { try? FileManager.default.removeItem(at: directory) }

        try persistence.save(PackSetAssignment(addedToolsByPack: [mail.id: [mail.tools[0]]]), agent: "agent-id")
        let file = persistence.recordURL(agent: "agent-id")
        XCTAssertEqual(mode(at: directory), 0o700)
        XCTAssertEqual(mode(at: file), 0o600)

        XCTAssertEqual(chmod(directory.path, 0o777), 0)
        XCTAssertEqual(chmod(file.path, 0o644), 0)
        XCTAssertFalse(persistence.load(agent: "agent-id").isEmpty)
        XCTAssertEqual(mode(at: directory), 0o700)
        XCTAssertEqual(mode(at: file), 0o600)
    }

    func testJournalLoaderRefusesSymlinkToAnotherAgentsRecord() throws {
        let (directory, persistence) = temporaryPersistence()
        defer { try? FileManager.default.removeItem(at: directory) }
        try persistence.save(PackSetAssignment(addedToolsByPack: [mail.id: mail.tools]), agent: "first-agent-id")
        let firstRecord = persistence.recordURL(agent: "first-agent-id")
        let secondRecord = persistence.recordURL(agent: "second-agent-id")
        try FileManager.default.createSymbolicLink(at: secondRecord, withDestinationURL: firstRecord)

        XCTAssertTrue(persistence.load(agent: "second-agent-id").isEmpty)
        XCTAssertEqual(persistence.load(agent: "first-agent-id").recordsByPackID[mail.id]?.intendedAdded, mail.tools)
    }

    func testJournalLoaderRefusesFIFOWithoutBlocking() throws {
        let (directory, persistence) = temporaryPersistence()
        defer { try? FileManager.default.removeItem(at: directory) }
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let fifo = persistence.recordURL(agent: "fifo-agent")
        XCTAssertEqual(fifo.path.withCString { Darwin.mkfifo($0, mode_t(0o600)) }, 0)

        let start = Date()
        XCTAssertTrue(persistence.load(agent: "fifo-agent").isEmpty)
        XCTAssertLessThan(Date().timeIntervalSince(start), 1, "loading a FIFO must not block")
    }

    func testPruningFIFOJournalDoesNotBlock() throws {
        let (directory, persistence) = temporaryPersistence()
        defer { try? FileManager.default.removeItem(at: directory) }
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let fifo = persistence.recordURL(agent: "orphan-fifo")
        XCTAssertEqual(fifo.path.withCString { Darwin.mkfifo($0, mode_t(0o600)) }, 0)

        let start = Date()
        persistence.pruneOrphans(existingAgentIDs: [])
        XCTAssertLessThan(Date().timeIntervalSince(start), 1, "pruning a FIFO must not block")
        XCTAssertTrue(FileManager.default.fileExists(atPath: fifo.path))
    }

    func testDuplicateJSONKeysAreRejected() throws {
        try assertJournalRejected(#"{"version":1,"agentID":"agent-id","recordsByPackID":{"mail":{"packID":"mail","preExistingTools":[],"intendedAdded":[],"state":"active","state":"active"}},"pendingRemovalsByPackID":{}}"#)
    }

    func testEscapedDuplicateJSONKeysAreRejected() throws {
        try assertJournalRejected(#"{"version":1,"agentID":"agent-id","recordsByPackID":{"mail":{"packID":"mail","preExistingTools":[],"intendedAdded":[],"state":"active","st\u0061te":"active"}},"pendingRemovalsByPackID":{}}"#)
    }

    func testNestedDuplicateJSONKeysAreRejected() throws {
        try assertJournalRejected(#"{"version":1,"agentID":"agent-id","recordsByPackID":{},"pendingRemovalsByPackID":{},"extra":{"key":1,"key":2}}"#)
    }

    func testDuplicateJSONKeysInsideArrayObjectsAreRejected() throws {
        try assertJournalRejected(#"{"version":1,"agentID":"agent-id","recordsByPackID":{},"pendingRemovalsByPackID":{},"extra":[{"key":1,"key":2}]}"#)
    }

    private func assertJournalRejected(_ rawJSON: String, file: StaticString = #filePath, line: UInt = #line) throws {
        let (directory, persistence) = temporaryPersistence()
        defer { try? FileManager.default.removeItem(at: directory) }
        try writeRaw(Data(rawJSON.utf8), agent: "agent-id", persistence: persistence)
        XCTAssertTrue(persistence.load(agent: "agent-id").isEmpty, file: file, line: line)
    }

    func testJournalDirectorySymlinkIsRefused() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("tool-pack-dir-link-\(UUID().uuidString)", isDirectory: true)
        let realDirectory = root.appendingPathComponent("real", isDirectory: true)
        let linkedDirectory = root.appendingPathComponent("linked", isDirectory: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let realPersistence = PackAssignmentPersistence(directory: realDirectory)
        try realPersistence.save(PackSetAssignment(addedToolsByPack: [mail.id: mail.tools]), agent: "agent-id")
        try FileManager.default.createSymbolicLink(at: linkedDirectory, withDestinationURL: realDirectory)
        let linkedPersistence = PackAssignmentPersistence(directory: linkedDirectory)

        XCTAssertTrue(linkedPersistence.load(agent: "agent-id").isEmpty)
        XCTAssertThrowsError(try linkedPersistence.save(PackSetAssignment(), agent: "agent-id"))
    }

    func testJournalFilenameHashesStableAgentIDAndDoesNotReuseADeletedAgentsRecord() throws {
        let (directory, persistence) = temporaryPersistence()
        defer { try? FileManager.default.removeItem(at: directory) }
        let displayName = "Builder"
        let deletedAgentID = "stable-old-42"
        let replacementAgentID = "stable-new-93"
        try persistence.save(PackSetAssignment(addedToolsByPack: [mail.id: mail.tools]), agent: deletedAgentID)
        let oldFilename = persistence.recordURL(agent: deletedAgentID).lastPathComponent

        XCTAssertEqual(oldFilename.count, 69)
        XCTAssertFalse(oldFilename.contains(displayName))
        XCTAssertFalse(oldFilename.contains(deletedAgentID))
        persistence.delete(agent: deletedAgentID)
        XCTAssertTrue(persistence.load(agent: replacementAgentID).isEmpty)
        try persistence.save(PackSetAssignment(addedToolsByPack: [agenda.id: agenda.tools]), agent: replacementAgentID)
        XCTAssertNotEqual(persistence.recordURL(agent: deletedAgentID), persistence.recordURL(agent: replacementAgentID))
        XCTAssertEqual(persistence.load(agent: replacementAgentID).packIDs, [agenda.id])
    }

    func testOrphanJournalsAreDeletedAndExistingAgentsWithNoOwnedToolsAreDropped() throws {
        let (directory, persistence) = temporaryPersistence()
        defer { try? FileManager.default.removeItem(at: directory) }
        try persistence.save(PackSetAssignment(addedToolsByPack: [mail.id: mail.tools]), agent: "orphan-id")
        try persistence.save(PackSetAssignment(addedToolsByPack: [agenda.id: agenda.tools]), agent: "existing-id")

        persistence.pruneOrphans(existingAgentIDs: ["existing-id"])
        XCTAssertFalse(FileManager.default.fileExists(atPath: persistence.recordURL(agent: "orphan-id").path))
        var current = persistence.load(agent: "existing-id")
        current.reconcilePending(with: [])
        XCTAssertTrue(current.isEmpty)
        persistence.delete(agent: "existing-id")
        XCTAssertFalse(FileManager.default.fileExists(atPath: persistence.recordURL(agent: "existing-id").path))
    }

    func testVersion999RecordFallsBackToAnEmptyJournal() throws {
        let (directory, persistence) = temporaryPersistence()
        defer { try? FileManager.default.removeItem(at: directory) }
        try writeRaw(rawRecord(agentID: "agent-id", version: 999), agent: "agent-id", persistence: persistence)

        XCTAssertTrue(persistence.load(agent: "agent-id").isEmpty)
    }

    func testJournalWithWrongEmbeddedAgentIDIsRejected() throws {
        let (directory, persistence) = temporaryPersistence()
        defer { try? FileManager.default.removeItem(at: directory) }
        try persistence.save(PackSetAssignment(addedToolsByPack: [mail.id: mail.tools]), agent: "other-agent-id")
        try FileManager.default.copyItem(
            at: persistence.recordURL(agent: "other-agent-id"),
            to: persistence.recordURL(agent: "requested-agent-id")
        )

        XCTAssertTrue(persistence.load(agent: "requested-agent-id").isEmpty)
    }

    func testIntersectingProvenanceIsRejected() throws {
        let (directory, persistence) = temporaryPersistence()
        defer { try? FileManager.default.removeItem(at: directory) }
        let badRecord: [String: Any] = [
            "packID": mail.id,
            "preExistingTools": [mail.tools[0]],
            "intendedAdded": [mail.tools[0]],
            "state": "applied",
        ]
        try writeRaw(rawRecord(agentID: "agent-id", records: [mail.id: badRecord]), agent: "agent-id", persistence: persistence)

        XCTAssertTrue(persistence.load(agent: "agent-id").isEmpty)
    }

    func testUnsafeToolIdentifierIsRejected() throws {
        let (directory, persistence) = temporaryPersistence()
        defer { try? FileManager.default.removeItem(at: directory) }
        let badRecord: [String: Any] = [
            "packID": mail.id,
            "preExistingTools": [],
            "intendedAdded": ["mail/read"],
            "state": "applied",
        ]
        try writeRaw(rawRecord(agentID: "agent-id", records: [mail.id: badRecord]), agent: "agent-id", persistence: persistence)

        XCTAssertTrue(persistence.load(agent: "agent-id").isEmpty)
    }

    func testOversizedJournalIsRefusedBeforeReading() throws {
        let (directory, persistence) = temporaryPersistence()
        defer { try? FileManager.default.removeItem(at: directory) }
        try writeRaw(Data(repeating: 0x41, count: 1024 * 1024 + 1), agent: "agent-id", persistence: persistence)

        XCTAssertTrue(persistence.load(agent: "agent-id").isEmpty)
    }

    func testUnknownOrMissingRequiredJournalFieldsAreRejected() throws {
        let (directory, persistence) = temporaryPersistence()
        defer { try? FileManager.default.removeItem(at: directory) }
        let incomplete = try JSONSerialization.data(withJSONObject: [
            "version": 1,
            "agentID": "agent-id",
            "recordsByPackID": [:] as [String: String],
            "unexpected": true,
        ])
        try writeRaw(incomplete, agent: "agent-id", persistence: persistence)

        XCTAssertTrue(persistence.load(agent: "agent-id").isEmpty)
    }

    func testJournalWithMoreThanTwentyFourPackRecordsIsRejected() throws {
        let (directory, persistence) = temporaryPersistence()
        defer { try? FileManager.default.removeItem(at: directory) }
        var records: [String: Any] = [:]
        for index in 0..<25 {
            let packID = "pack_\(index)"
            records[packID] = [
                "packID": packID,
                "preExistingTools": [],
                "intendedAdded": ["tool_\(index)"],
                "state": "applied",
            ] as [String: Any]
        }
        try writeRaw(rawRecord(agentID: "agent-id", records: records), agent: "agent-id", persistence: persistence)

        XCTAssertTrue(persistence.load(agent: "agent-id").isEmpty)
    }
}
