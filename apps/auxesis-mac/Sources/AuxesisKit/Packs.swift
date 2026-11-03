import Foundation
import CryptoKit
import Darwin

public struct ToolPack: Equatable, Identifiable {
    public let id: String
    public let titleKey: StringKey
    public let descriptionKey: StringKey
    public let tools: [String]
    public let requires_apps: [String]

    public init(
        id: String,
        titleKey: StringKey,
        descriptionKey: StringKey,
        tools: [String],
        requires_apps: [String]
    ) {
        self.id = id
        self.titleKey = titleKey
        self.descriptionKey = descriptionKey
        self.tools = tools
        self.requires_apps = requires_apps
    }
}

public enum ToolPacks {
    public static let maximumToolsPerAgent = 24
    public static let presets: [ToolPack] = [
        ToolPack(
            id: "mail",
            titleKey: .packMailTitle,
            descriptionKey: .packMailDescription,
            tools: ["mail_list", "mail_search", "mail_read", "mail_draft", "mail_send"],
            requires_apps: ["Mail"]
        ),
        ToolPack(
            id: "agenda",
            titleKey: .packAgendaTitle,
            descriptionKey: .packAgendaDescription,
            tools: ["calendar_list", "calendar_create_event"],
            requires_apps: ["Agenda"]
        ),
        ToolPack(
            id: "recherche-web",
            titleKey: .packWebSearchTitle,
            descriptionKey: .packWebSearchDescription,
            tools: ["http_fetch"],
            requires_apps: []
        ),
    ]

    /// Keep the owner's order and append only tools present in the live registry.
    public static func union(current: [String]?, pack: ToolPack, available: Set<String>) -> [String] {
        // The API normalizes allowlists by keeping each tool's first occurrence.
        var result: [String] = []
        for tool in current ?? [] where !result.contains(tool) { result.append(tool) }
        for tool in pack.tools where available.contains(tool) && !result.contains(tool) {
            result.append(tool)
        }
        return result
    }

    public static func availableTools(for pack: ToolPack, registry: Set<String>) -> [String] {
        pack.tools.filter(registry.contains)
    }

    public static func fitsAgentLimit(current: [String]?, pack: ToolPack, available: Set<String>) -> Bool {
        union(current: current, pack: pack, available: available).count <= maximumToolsPerAgent
    }

    public static func isReady(_ pack: ToolPack, registry: Set<String>) -> Bool {
        pack.requires_apps.isEmpty || !availableTools(for: pack, registry: registry).isEmpty
    }

    /// A pack changes only the allowlist. An explicit refusal remains the floor.
    public static func canCall(tool: String, allowlist: [String], deniedTools: Set<String>) -> Bool {
        allowlist.contains(tool) && !deniedTools.contains(tool)
    }

    /// Plain words for the tools exposed by the built-in packs. Never surface
    /// registry identifiers in the interface.
    public static func label(for tool: String, _ language: Language) -> String {
        switch tool {
        case "mail_list": return L10n.t(.packToolMailList, language)
        case "mail_search": return L10n.t(.packToolMailSearch, language)
        case "mail_read": return L10n.t(.packToolMailRead, language)
        case "mail_draft": return L10n.t(.packToolMailDraft, language)
        case "mail_send": return L10n.t(.packToolMailSend, language)
        case "calendar_list": return L10n.t(.packToolCalendarList, language)
        case "calendar_create_event": return L10n.t(.packToolCalendarCreate, language)
        case "http_fetch": return L10n.t(.packToolHttpFetch, language)
        default: return L10n.t(.packToolUnknown, language)
        }
    }

    public static func diffText(previous: [String], current: [String], _ language: Language) -> String {
        let added = current.filter { !previous.contains($0) }
        let removed = previous.filter { !current.contains($0) }
        let lines = added.map { "+ \(label(for: $0, language))" }
            + removed.map { "− \(label(for: $0, language))" }
        return lines.isEmpty ? L10n.t(.packNoChange, language) : lines.joined(separator: "   ")
    }

    /// The API keeps only the first occurrence of each tool, in input order.
    public static func normalized(_ tools: [String]?) -> [String]? {
        guard let tools else { return nil }
        var result: [String] = []
        for tool in tools where !result.contains(tool) { result.append(tool) }
        return result
    }

    /// A lost PUT response is successful when a fresh read shows the desired list.
    public static func reconciled(expected: [String]?, live: [String]?) -> Bool {
        normalized(expected) == normalized(live)
    }
}

public enum PackAssignmentState: String, Codable {
    case pending
    case applied
}

/// A write-ahead assignment record. `intendedAdded` is cumulative across
/// retries; `preExistingTools` excludes tools already owned by this pack.
public struct PackOwnershipRecord: Codable, Equatable {
    public var packID: String
    public var preExistingTools: [String]
    public var intendedAdded: [String]
    public var state: PackAssignmentState

    public init(packID: String, preExistingTools: [String], intendedAdded: [String], state: PackAssignmentState) {
        self.packID = packID
        self.preExistingTools = preExistingTools
        self.intendedAdded = intendedAdded
        self.state = state
    }
}

/// Kept as a source-compatible value for older callers and persisted formats.
public struct PackAssignment: Codable, Equatable {
    public let packID: String
    public let addedTools: [String]

    public init(packID: String, addedTools: [String]) {
        self.packID = packID
        self.addedTools = addedTools
    }
}

public struct PackRemovalRecord: Codable, Equatable {
    public var packID: String
    public var intendedRemoved: [String]

    public init(packID: String, intendedRemoved: [String]) {
        self.packID = packID
        self.intendedRemoved = intendedRemoved
    }
}

/// Per-agent write-ahead journal for assignment and removal PUTs.
public struct PackSetAssignment: Codable, Equatable {
    public private(set) var recordsByPackID: [String: PackOwnershipRecord]
    public private(set) var pendingRemovalsByPackID: [String: PackRemovalRecord]

    /// Compatibility/read convenience: these are the cumulative intended tools.
    public var addedToolsByPack: [String: [String]] {
        recordsByPackID.mapValues(\.intendedAdded)
    }
    public var packIDs: Set<String> { Set(recordsByPackID.keys) }
    public var isEmpty: Bool { recordsByPackID.isEmpty && pendingRemovalsByPackID.isEmpty }
    public var hasPendingWork: Bool {
        recordsByPackID.values.contains(where: { $0.state == .pending }) || !pendingRemovalsByPackID.isEmpty
    }

    private enum CodingKeys: String, CodingKey {
        case recordsByPackID, pendingRemovalsByPackID
        case addedToolsByPack, packIDs, previousTools
    }

    public init(addedToolsByPack: [String: [String]] = [:]) {
        self.recordsByPackID = Dictionary(uniqueKeysWithValues: addedToolsByPack.map { packID, tools in
            (packID, PackOwnershipRecord(
                packID: packID,
                preExistingTools: [],
                intendedAdded: Self.unique(tools),
                state: .applied
            ))
        })
        self.pendingRemovalsByPackID = [:]
    }

    public init() {
        recordsByPackID = [:]
        pendingRemovalsByPackID = [:]
    }

    fileprivate init(
        recordsByPackID: [String: PackOwnershipRecord],
        pendingRemovalsByPackID: [String: PackRemovalRecord]
    ) {
        self.recordsByPackID = recordsByPackID
        self.pendingRemovalsByPackID = pendingRemovalsByPackID
    }

    public init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        if let records = try values.decodeIfPresent([String: PackOwnershipRecord].self, forKey: .recordsByPackID) {
            recordsByPackID = records
            pendingRemovalsByPackID = try values.decodeIfPresent([String: PackRemovalRecord].self, forKey: .pendingRemovalsByPackID) ?? [:]
            return
        }

        // Migrate the previous on-disk shape without guessing ownership of any
        // currently present tools. Old records already contained provenance.
        if let records = try values.decodeIfPresent([String: [String]].self, forKey: .addedToolsByPack) {
            recordsByPackID = Dictionary(uniqueKeysWithValues: records.map { packID, tools in
                (packID, PackOwnershipRecord(
                    packID: packID,
                    preExistingTools: [],
                    intendedAdded: Self.unique(tools),
                    state: .applied
                ))
            })
            pendingRemovalsByPackID = [:]
            return
        }

        // Migrate the oldest shape by excluding the captured pre-assignment list.
        let ids = try values.decodeIfPresent(Set<String>.self, forKey: .packIDs) ?? []
        let previous = try values.decodeIfPresent([String].self, forKey: .previousTools) ?? []
        recordsByPackID = Dictionary(uniqueKeysWithValues: ids.map { id in
            let tools = ToolPacks.presets.first(where: { $0.id == id })?.tools ?? []
            return (id, PackOwnershipRecord(
                packID: id,
                preExistingTools: previous,
                intendedAdded: tools.filter { !previous.contains($0) },
                state: .applied
            ))
        })
        pendingRemovalsByPackID = [:]
    }

    public func encode(to encoder: Encoder) throws {
        var values = encoder.container(keyedBy: CodingKeys.self)
        try values.encode(recordsByPackID, forKey: .recordsByPackID)
        try values.encode(pendingRemovalsByPackID, forKey: .pendingRemovalsByPackID)
    }

    /// Saves a pending record before the caller sends the PUT.
    @discardableResult
    public mutating func prepareAssignment(pack: ToolPack, liveTools: [String]?, available: Set<String>) -> [String] {
        let live = Self.unique(liveTools ?? [])
        let previous = recordsByPackID[pack.id]
        let oldOwned = previous?.intendedAdded ?? []
        let newlyIntroduced = pack.tools.filter { available.contains($0) && !live.contains($0) }
        let intended = Self.unique(oldOwned + newlyIntroduced)
        let intendedSet = Set(intended)
        recordsByPackID[pack.id] = PackOwnershipRecord(
            packID: pack.id,
            preExistingTools: live.filter { !intendedSet.contains($0) },
            intendedAdded: intended,
            state: .pending
        )
        let liveSet = Set(live)
        let desired = Self.unique(live + pack.tools.filter { available.contains($0) && !liveSet.contains($0) })
        return desired
    }

    public mutating func markAssignmentApplied(packID: String) {
        guard var record = recordsByPackID[packID] else { return }
        record.state = .applied
        recordsByPackID[packID] = record
    }

    /// A successful fresh read resolves pending assignments. The intended
    /// ownership stays cumulative; absent tools are harmless at removal time.
    public mutating func reconcilePending(with liveTools: [String]?) {
        let live = Set(liveTools ?? [])
        for packID in Array(recordsByPackID.keys) {
            guard var record = recordsByPackID[packID] else { continue }
            if !record.intendedAdded.contains(where: live.contains) {
                recordsByPackID.removeValue(forKey: packID)
                pendingRemovalsByPackID.removeValue(forKey: packID)
            } else if record.state == .pending {
                record.state = .applied
                recordsByPackID[packID] = record
            }
        }
        for packID in Array(pendingRemovalsByPackID.keys) {
            guard let removal = pendingRemovalsByPackID[packID] else { continue }
            if !removal.intendedRemoved.contains(where: live.contains) {
                confirmRemoval(packID: packID)
            }
        }
    }

    /// Writes a pending removal and returns the live list to PUT. The pending
    /// record remains until a fresh read proves all exclusive owned tools gone.
    @discardableResult
    public mutating func prepareRemoval(packID: String, liveTools: [String]?) -> [String]? {
        guard let record = recordsByPackID[packID] else { return nil }
        let live = Self.unique(liveTools ?? [])
        let protected = protectedTools(excluding: packID)
        let oldPending = pendingRemovalsByPackID[packID]?.intendedRemoved ?? []
        let toRemove = Self.unique(oldPending + record.intendedAdded.filter { live.contains($0) })
            .filter { live.contains($0) && !protected.contains($0) }
        pendingRemovalsByPackID[packID] = PackRemovalRecord(packID: packID, intendedRemoved: toRemove)
        let removeSet = Set(toRemove)
        return live.filter { !removeSet.contains($0) }
    }

    public func removalIsConfirmed(packID: String, liveTools: [String]?) -> Bool {
        guard let removal = pendingRemovalsByPackID[packID] else { return false }
        let live = Set(liveTools ?? [])
        return !removal.intendedRemoved.contains(where: live.contains)
    }

    public mutating func confirmRemoval(packID: String) {
        recordsByPackID.removeValue(forKey: packID)
        pendingRemovalsByPackID.removeValue(forKey: packID)
    }

    public func ownedTools(packID: String, liveTools: [String]?) -> [String] {
        let live = Set(liveTools ?? [])
        return recordsByPackID[packID]?.intendedAdded.filter(live.contains) ?? []
    }

    /// Compatibility helper for callers using the earlier pure planner API.
    public func removing(packID: String, liveTools: [String]?, registry: Set<String>) -> (tools: [String]?, assignment: PackSetAssignment?) {
        var updated = self
        let tools = updated.prepareRemoval(packID: packID, liveTools: liveTools)
        if tools == nil { return (liveTools, self) }
        if updated.pendingRemovalsByPackID[packID]?.intendedRemoved.isEmpty == true {
            updated.confirmRemoval(packID: packID)
        }
        return (tools, updated.isEmpty ? nil : updated)
    }

    private func protectedTools(excluding packID: String) -> Set<String> {
        Set(recordsByPackID.values.compactMap { record -> ToolPack? in
            guard record.packID != packID, record.state == .applied else { return nil }
            return ToolPacks.presets.first(where: { $0.id == record.packID })
        }.flatMap(\.tools))
    }

    private static func unique(_ tools: [String]) -> [String] {
        var seen = Set<String>()
        return tools.filter { seen.insert($0).inserted }
    }
}

/// Private, versioned on-disk envelope. The agent id binds the contents to the
/// hashed filename and prevents a copied or stale record claiming another agent.
private struct PersistedPackJournal: Decodable {
    let version: Int
    let agentID: String
    let recordsByPackID: [String: PackOwnershipRecord]
    let pendingRemovalsByPackID: [String: PackRemovalRecord]
}

/// Atomic per-agent persistence for the write-ahead journal. The journal only
/// contains pack ids and tool names; it never stores credentials or secrets.
public final class PackAssignmentPersistence {
    public static let shared = PackAssignmentPersistence(legacyDefaults: .standard)

    private static let lock = NSRecursiveLock()
    private static let currentVersion = 1
    private static let maximumFileSize = 64 * 1024
    private static let maximumToolCount = ToolPacks.maximumToolsPerAgent
    private static let maximumRecordCount = 24
    private let directory: URL
    private let legacyDefaults: UserDefaults?
    private var activeAgents: Set<String> = []

    public init(directory: URL? = nil, legacyDefaults: UserDefaults? = nil) {
        self.legacyDefaults = legacyDefaults
        if let directory {
            self.directory = directory
        } else {
            let support = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first
                ?? FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Library/Application Support", isDirectory: true)
            self.directory = support.appendingPathComponent("Auxesis/tool-pack-assignments", isDirectory: true)
        }
    }

    public func recordURL(agent: String) -> URL {
        let digest = SHA256.hash(data: Data(agent.utf8))
        let filename = digest.map { String(format: "%02x", $0) }.joined()
        return directory.appendingPathComponent("\(filename).json")
    }

    public func load(agent: String) -> PackSetAssignment {
        Self.lock.lock()
        defer { Self.lock.unlock() }
        let directoryFD: Int32
        do {
            guard let opened = try openJournalDirectory(create: false) else {
                return migrateLegacyRecordIfPresent(agent: agent)
            }
            directoryFD = opened
        } catch {
            return PackSetAssignment()
        }
        defer { Darwin.close(directoryFD) }

        switch readRecord(named: recordURL(agent: agent).lastPathComponent, from: directoryFD) {
        case .missing:
            return migrateLegacyRecordIfPresent(agent: agent)
        case .refused:
            return PackSetAssignment()
        case .data(let data):
            guard let decoded = decodeRecord(data, expectedAgentID: agent) else { return PackSetAssignment() }
            return decoded.journal
        }
    }

    /// Writes a private temporary file, fsyncs it, then atomically renames it
    /// over the prior record. A failed write must prevent the PUT.
    public func save(_ journal: PackSetAssignment, agent: String) throws {
        Self.lock.lock()
        defer { Self.lock.unlock() }
        guard Self.isValid(journal) else { throw Self.persistenceError(EINVAL) }
        let data = try Self.encode(journal, agentID: agent)
        guard data.count <= Self.maximumFileSize else { throw Self.persistenceError(EFBIG) }

        let directoryFD = try openJournalDirectory(create: true)!
        defer { Darwin.close(directoryFD) }

        let finalName = recordURL(agent: agent).lastPathComponent
        let temporaryName = ".tmp-\(UUID().uuidString)"
        let fileFD = temporaryName.withCString {
            Darwin.openat(directoryFD, $0, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC, mode_t(S_IRUSR | S_IWUSR))
        }
        guard fileFD >= 0 else { throw Self.currentPersistenceError() }
        var shouldClose = true
        defer {
            if shouldClose { Darwin.close(fileFD) }
            _ = temporaryName.withCString { Darwin.unlinkat(directoryFD, $0, 0) }
        }

        guard Darwin.fchmod(fileFD, mode_t(S_IRUSR | S_IWUSR)) == 0 else { throw Self.currentPersistenceError() }
        try Self.writeAll(data, to: fileFD)
        guard Darwin.fsync(fileFD) == 0 else { throw Self.currentPersistenceError() }
        guard Darwin.close(fileFD) == 0 else {
            shouldClose = false
            throw Self.currentPersistenceError()
        }
        shouldClose = false

        let renameResult = temporaryName.withCString { temporary in
            finalName.withCString { final in Darwin.renameat(directoryFD, temporary, directoryFD, final) }
        }
        guard renameResult == 0 else { throw Self.currentPersistenceError() }
        guard Darwin.fsync(directoryFD) == 0 else { throw Self.currentPersistenceError() }
    }

    /// Removes valid journals for ids that no longer exist. Entries are read
    /// through the already-open directory descriptor and only regular files
    /// whose embedded id matches their hashed filename are eligible.
    public func pruneOrphans(existingAgentIDs: Set<String>) {
        Self.lock.lock()
        defer { Self.lock.unlock() }
        guard let directoryFD = try? openJournalDirectory(create: false) else { return }
        defer { Darwin.close(directoryFD) }
        guard let entries = try? FileManager.default.contentsOfDirectory(atPath: directory.path) else { return }

        for entry in entries where Self.isJournalFilename(entry) {
            guard case .data(let data) = readRecord(named: entry, from: directoryFD),
                  let stored = decodeRecord(data, expectedAgentID: nil),
                  recordURL(agent: stored.agentID).lastPathComponent == entry,
                  (!existingAgentIDs.contains(stored.agentID) || stored.journal.isEmpty) else { continue }
            _ = entry.withCString { Darwin.unlinkat(directoryFD, $0, 0) }
        }
        _ = Darwin.fsync(directoryFD)
    }

    /// Removes a regular record through a verified directory descriptor.
    public func delete(agent: String) {
        Self.lock.lock()
        defer { Self.lock.unlock() }
        guard let directoryFD = try? openJournalDirectory(create: false) else { return }
        defer { Darwin.close(directoryFD) }
        let filename = recordURL(agent: agent).lastPathComponent
        var info = stat()
        guard filename.withCString({ Darwin.fstatat(directoryFD, $0, &info, AT_SYMLINK_NOFOLLOW) }) == 0,
              (info.st_mode & mode_t(S_IFMT)) == mode_t(S_IFREG) else { return }
        guard filename.withCString({ Darwin.unlinkat(directoryFD, $0, 0) }) == 0 else { return }
        _ = Darwin.fsync(directoryFD)
    }

    /// Prevents simultaneous UI actions for one agent, including double taps
    /// that arrive before SwiftUI redraws disabled buttons.
    public func beginOperation(agent: String) -> Bool {
        Self.lock.lock()
        defer { Self.lock.unlock() }
        guard !activeAgents.contains(agent) else { return false }
        activeAgents.insert(agent)
        return true
    }

    public func endOperation(agent: String) {
        Self.lock.lock()
        defer { Self.lock.unlock() }
        activeAgents.remove(agent)
    }

    private enum ReadResult {
        case missing
        case refused
        case data(Data)
    }

    private func migrateLegacyRecordIfPresent(agent: String) -> PackSetAssignment {
        guard let legacyData = legacyDefaults?.data(forKey: "auxesis.pack-assignment.\(agent)"),
              let migrated = try? JSONDecoder().decode(PackSetAssignment.self, from: legacyData),
              Self.isValid(migrated) else { return PackSetAssignment() }
        if (try? save(migrated, agent: agent)) != nil {
            legacyDefaults?.removeObject(forKey: "auxesis.pack-assignment.\(agent)")
        }
        return migrated
    }

    /// lstat rejects a symlink at the journal directory itself; open adds a
    /// second O_NOFOLLOW check to close the race before chmod or file access.
    private func openJournalDirectory(create: Bool) throws -> Int32? {
        if create {
            try FileManager.default.createDirectory(
                at: directory,
                withIntermediateDirectories: true,
                attributes: [.posixPermissions: NSNumber(value: 0o700)]
            )
        }

        var info = stat()
        guard lstat(directory.path, &info) == 0 else {
            if !create && errno == ENOENT { return nil }
            throw Self.currentPersistenceError()
        }
        guard (info.st_mode & mode_t(S_IFMT)) == mode_t(S_IFDIR) else {
            throw Self.persistenceError(ELOOP)
        }
        let directoryFD = directory.path.withCString {
            Darwin.open($0, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
        }
        guard directoryFD >= 0 else { throw Self.currentPersistenceError() }
        guard Darwin.fchmod(directoryFD, mode_t(S_IRWXU)) == 0 else {
            let error = Self.currentPersistenceError()
            Darwin.close(directoryFD)
            throw error
        }
        return directoryFD
    }

    /// Opens without following links or blocking on special files, checks type
    /// and size on that descriptor, then reads only through it. Existing modes
    /// are tightened to 0600.
    private func readRecord(named name: String, from directoryFD: Int32) -> ReadResult {
        let fileFD = name.withCString {
            Darwin.openat(directoryFD, $0, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
        }
        guard fileFD >= 0 else { return errno == ENOENT ? .missing : .refused }
        defer { Darwin.close(fileFD) }

        var info = stat()
        guard Darwin.fstat(fileFD, &info) == 0,
              (info.st_mode & mode_t(S_IFMT)) == mode_t(S_IFREG),
              Darwin.fchmod(fileFD, mode_t(S_IRUSR | S_IWUSR)) == 0,
              info.st_size >= 0,
              info.st_size <= off_t(Self.maximumFileSize) else { return .refused }

        var data = Data()
        var buffer = [UInt8](repeating: 0, count: 8 * 1024)
        while true {
            let count = Darwin.read(fileFD, &buffer, buffer.count)
            if count == 0 { break }
            if count < 0 {
                if errno == EINTR { continue }
                return .refused
            }
            guard data.count + count <= Self.maximumFileSize else { return .refused }
            data.append(contentsOf: buffer.prefix(count))
        }
        return .data(data)
    }

    private func decodeRecord(_ data: Data, expectedAgentID: String?) -> (agentID: String, journal: PackSetAssignment)? {
        guard Self.hasNoDuplicateJSONKeys(data),
              let root = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              Set(root.keys) == Set(["version", "agentID", "recordsByPackID", "pendingRemovalsByPackID"]),
              let records = root["recordsByPackID"] as? [String: Any],
              let removals = root["pendingRemovalsByPackID"] as? [String: Any],
              records.count + removals.count <= Self.maximumRecordCount else { return nil }

        for (packID, rawRecord) in records {
            guard let record = rawRecord as? [String: Any],
                  Set(record.keys) == Set(["packID", "preExistingTools", "intendedAdded", "state"]),
                  record["packID"] as? String == packID else { return nil }
        }
        for (packID, rawRecord) in removals {
            guard let record = rawRecord as? [String: Any],
                  Set(record.keys) == Set(["packID", "intendedRemoved"]),
                  record["packID"] as? String == packID else { return nil }
        }

        guard let envelope = try? JSONDecoder().decode(PersistedPackJournal.self, from: data),
              envelope.version == Self.currentVersion,
              !envelope.agentID.isEmpty,
              expectedAgentID == nil || envelope.agentID == expectedAgentID,
              envelope.recordsByPackID.count + envelope.pendingRemovalsByPackID.count <= Self.maximumRecordCount else { return nil }
        let journal = PackSetAssignment(
            recordsByPackID: envelope.recordsByPackID,
            pendingRemovalsByPackID: envelope.pendingRemovalsByPackID
        )
        guard Self.isValid(journal) else { return nil }
        return (envelope.agentID, journal)
    }

    private static func encode(_ journal: PackSetAssignment, agentID: String) throws -> Data {
        let object: [String: Any] = [
            "version": currentVersion,
            "agentID": agentID,
            "recordsByPackID": journal.recordsByPackID.mapValues { record in
                [
                    "packID": record.packID,
                    "preExistingTools": record.preExistingTools,
                    "intendedAdded": record.intendedAdded,
                    "state": record.state.rawValue,
                ] as [String: Any]
            },
            "pendingRemovalsByPackID": journal.pendingRemovalsByPackID.mapValues { record in
                ["packID": record.packID, "intendedRemoved": record.intendedRemoved] as [String: Any]
            },
        ]
        guard JSONSerialization.isValidJSONObject(object) else { throw persistenceError(EINVAL) }
        return try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
    }

    /// JSONSerialization silently keeps one value when an object contains the
    /// same key more than once. Scan the complete value first so every object,
    /// including objects nested in arrays, has unambiguous keys.
    private static func hasNoDuplicateJSONKeys(_ data: Data) -> Bool {
        var scanner = JSONDuplicateKeyScanner(bytes: Array(data))
        return scanner.scan()
    }

    private struct JSONDuplicateKeyScanner {
        let bytes: [UInt8]
        var index = 0

        mutating func scan() -> Bool {
            skipWhitespace()
            guard parseValue(depth: 0) else { return false }
            skipWhitespace()
            return index == bytes.count
        }

        private mutating func parseValue(depth: Int) -> Bool {
            guard depth <= 128, index < bytes.count else { return false }
            switch bytes[index] {
            case 0x7B: return parseObject(depth: depth + 1) // {
            case 0x5B: return parseArray(depth: depth + 1) // [
            case 0x22: return skipString() != nil // string
            default: return parsePrimitive()
            }
        }

        private mutating func parseObject(depth: Int) -> Bool {
            index += 1 // {
            skipWhitespace()
            if consume(0x7D) { return true } // }
            var keys = Set<Data>()
            while true {
                skipWhitespace()
                guard let key = readString(), keys.insert(Data(key.utf8)).inserted else { return false }
                skipWhitespace()
                guard consume(0x3A) else { return false } // :
                skipWhitespace()
                guard parseValue(depth: depth) else { return false }
                skipWhitespace()
                if consume(0x7D) { return true } // }
                guard consume(0x2C) else { return false } // ,
            }
        }

        private mutating func parseArray(depth: Int) -> Bool {
            index += 1 // [
            skipWhitespace()
            if consume(0x5D) { return true } // ]
            while true {
                skipWhitespace()
                guard parseValue(depth: depth) else { return false }
                skipWhitespace()
                if consume(0x5D) { return true } // ]
                guard consume(0x2C) else { return false } // ,
            }
        }

        private mutating func readString() -> String? {
            guard let range = skipString() else { return nil }
            let token = Data(bytes[range])
            return (try? JSONSerialization.jsonObject(with: token, options: [.fragmentsAllowed])) as? String
        }

        /// Returns the byte range including quotes and advances past a JSON
        /// string. Escape syntax and UTF-8 validity are also checked by the
        /// JSONSerialization call for object keys and by the final parse.
        private mutating func skipString() -> Range<Int>? {
            guard consume(0x22) else { return nil } // "
            let start = index - 1
            while index < bytes.count {
                let byte = bytes[index]
                index += 1
                if byte == 0x22 { return start..<index } // "
                if byte == 0x5C { // \
                    guard index < bytes.count else { return nil }
                    index += 1
                } else if byte < 0x20 {
                    return nil
                }
            }
            return nil
        }

        private mutating func parsePrimitive() -> Bool {
            let start = index
            while index < bytes.count,
                  !isWhitespace(bytes[index]),
                  bytes[index] != 0x2C, bytes[index] != 0x5D, bytes[index] != 0x7D {
                index += 1
            }
            return index > start
        }

        private mutating func skipWhitespace() {
            while index < bytes.count, isWhitespace(bytes[index]) { index += 1 }
        }

        private mutating func consume(_ byte: UInt8) -> Bool {
            guard index < bytes.count, bytes[index] == byte else { return false }
            index += 1
            return true
        }

        private func isWhitespace(_ byte: UInt8) -> Bool {
            byte == 0x20 || byte == 0x09 || byte == 0x0A || byte == 0x0D
        }
    }

    private static func isValid(_ journal: PackSetAssignment) -> Bool {
        guard journal.recordsByPackID.count + journal.pendingRemovalsByPackID.count <= maximumRecordCount else { return false }
        for (packID, record) in journal.recordsByPackID {
            guard record.packID == packID,
                  isSafeIdentifier(packID),
                  validToolList(record.preExistingTools),
                  validToolList(record.intendedAdded),
                  Set(record.preExistingTools).isDisjoint(with: Set(record.intendedAdded)) else { return false }
        }
        for (packID, record) in journal.pendingRemovalsByPackID {
            guard record.packID == packID,
                  isSafeIdentifier(packID),
                  validToolList(record.intendedRemoved) else { return false }
        }
        return true
    }

    private static func validToolList(_ tools: [String]) -> Bool {
        tools.count <= maximumToolCount && Set(tools).count == tools.count && tools.allSatisfy(isSafeIdentifier)
    }

    private static func isSafeIdentifier(_ value: String) -> Bool {
        guard !value.isEmpty, value.utf8.count <= 64 else { return false }
        return value.utf8.allSatisfy { byte in
            (byte >= 48 && byte <= 57) || (byte >= 65 && byte <= 90) || (byte >= 97 && byte <= 122)
                || byte == 46 || byte == 95 || byte == 45
        }
    }

    private static func isJournalFilename(_ name: String) -> Bool {
        name.utf8.count == 69 && name.hasSuffix(".json")
            && name.utf8.prefix(64).allSatisfy { ($0 >= 48 && $0 <= 57) || ($0 >= 97 && $0 <= 102) }
    }

    private static func writeAll(_ data: Data, to fd: Int32) throws {
        try data.withUnsafeBytes { rawBuffer in
            guard let baseAddress = rawBuffer.baseAddress else { return }
            var offset = 0
            while offset < data.count {
                let written = Darwin.write(fd, baseAddress.advanced(by: offset), data.count - offset)
                if written < 0 {
                    if errno == EINTR { continue }
                    throw currentPersistenceError()
                }
                guard written > 0 else { throw persistenceError(EIO) }
                offset += written
            }
        }
    }

    private static func currentPersistenceError() -> NSError {
        persistenceError(errno)
    }

    private static func persistenceError(_ code: Int32) -> NSError {
        NSError(domain: NSPOSIXErrorDomain, code: Int(code))
    }
}
