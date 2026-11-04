// "What Aux knows": the memory page's wire shapes and its state.
// The daemon owns the store; the app only reads, edits and forgets. The wire
// is a grouped view, one edit, one delete, two suggestions.
import Foundation

/// One stored fact, as the daemon lists it.
public struct MemoryFact: Decodable, Equatable, Identifiable {
    public let id: String
    public let text: String
    /// A fixed label ("you told Aux"), never raw source text.
    public let source: String?
    public let savedAt: String?
    public let editable: Bool
    enum CodingKeys: String, CodingKey { case id, text, source, savedAt = "saved_at", editable }

    public init(id: String, text: String, source: String? = nil, savedAt: String? = nil, editable: Bool = true) {
        self.id = id
        self.text = text
        self.source = source
        self.savedAt = savedAt
        self.editable = editable
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        id = (try? c.decode(String.self, forKey: .id)) ?? String((try? c.decode(Int.self, forKey: .id)) ?? 0)
        text = (try? c.decode(String.self, forKey: .text)) ?? ""
        source = try? c.decode(String.self, forKey: .source)
        savedAt = try? c.decode(String.self, forKey: .savedAt)
        editable = (try? c.decode(Bool.self, forKey: .editable)) ?? true
    }
}

/// A pending suggestion: the owner keeps it or drops it.
public struct MemorySuggestion: Decodable, Equatable, Identifiable {
    public let id: String
    public let text: String
    public let source: String?
    enum CodingKeys: String, CodingKey { case id, text, source }

    public init(id: String, text: String, source: String? = nil) {
        self.id = id
        self.text = text
        self.source = source
    }
}

/// The four sections of the page, in the order it shows them.
public enum MemorySection: String, CaseIterable, Hashable {
    case aboutYou = "about_you"
    case rules
    case people
    case other

    public static let displayOrder: [MemorySection] = [.aboutYou, .rules, .people, .other]

    public var titleKey: UIKey {
        switch self {
        case .aboutYou: return .memoryAboutYou
        case .rules: return .memoryRules
        case .people: return .memoryPeople
        case .other: return .memoryOther
        }
    }
}

/// `GET /v1/agents/{id}/memory/view`: the sections and the pending suggestions.
public struct MemorySnapshot: Decodable, Equatable {
    public let agent: String
    public var groups: [String: [MemoryFact]]
    public var suggestions: [MemorySuggestion]
    private struct Group: Decodable { let key: String; let items: [MemoryFact] }
    private enum CodingKeys: String, CodingKey { case agent, groups, suggestions }

    public init(agent: String, groups: [String: [MemoryFact]], suggestions: [MemorySuggestion]) {
        self.agent = agent
        self.groups = groups
        self.suggestions = suggestions
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        agent = (try? c.decode(String.self, forKey: .agent)) ?? ""
        let raw = (try? c.decode([Group].self, forKey: .groups)) ?? []
        groups = Dictionary(raw.map { ($0.key, $0.items) }, uniquingKeysWith: { _, last in last })
        suggestions = (try? c.decode([MemorySuggestion].self, forKey: .suggestions)) ?? []
    }
}

/// The four memory routes.
public protocol MemoryClient: AnyObject {
    /// `GET /v1/agents/{id}/memory/view`
    func memorySnapshot(agent: String) async throws -> MemorySnapshot
    /// `PATCH /v1/agents/{id}/memory/{item}` with `{"text": …}`
    func updateMemory(agent: String, item: String, text: String) async throws -> MemoryFact
    /// `DELETE /v1/agents/{id}/memory/{item}`
    func forgetMemory(agent: String, item: String) async throws
    /// `POST /v1/agents/{id}/memory/suggestions/{id}/accept`
    func acceptMemorySuggestion(agent: String, suggestion: String) async throws -> MemoryFact
    /// `POST /v1/agents/{id}/memory/suggestions/{id}/reject`
    func rejectMemorySuggestion(agent: String, suggestion: String) async throws
}

/// Why an action did not work, in the page's own words.
public enum MemoryProblem: Equatable {
    case offline, invalidText, gone, unavailable, failed

    public init(_ error: Error) {
        guard let error = error as? AuxdError else { self = .failed; return }
        switch (error, error.apiErrorCode) {
        case (.transport, _): self = .offline
        case (.http(400, _), "invalid_text"): self = .invalidText
        case (.http(404, _), _): self = .gone
        default: self = .failed
        }
    }

    public var key: UIKey {
        switch self {
        case .offline: return .memoryErrOffline
        case .invalidText: return .memoryErrInvalidText
        case .gone: return .memoryErrGone
        case .unavailable: return .memoryUnavailable
        case .failed: return .memoryErrFailed
        }
    }
}

/// The page's own words for what the daemon sends.
public enum MemoryText {
    /// The source line: the daemon's fixed label, translated when we know it.
    /// A label we do not know is shown exactly as it arrived.
    public static func source(_ raw: String?, language: Language) -> String {
        switch raw {
        case "you told Aux": return L10n.ui(.memorySourceTold, language)
        case "learned from a mail": return L10n.ui(.memorySourceMail, language)
        case "accepted suggestion": return L10n.ui(.memorySourceAccepted, language)
        case "older note": return L10n.ui(.memorySourceOlder, language)
        default: return raw ?? ""
        }
    }

    /// "12 Oct" / "12 oct." from the daemon's stamp; nil when there is none.
    public static func day(_ stamp: String?, language: Language) -> String? {
        guard let date = TimeText.parse(stamp) else { return nil }
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: language.localeIdentifier)
        formatter.dateFormat = "d MMM"
        return formatter.string(from: date)
    }
}

/// The page's state: the read, the inline editor, the delete confirmation and
/// the one error line.
@MainActor public final class MemoryPageModel: ObservableObject {
    /// The daemon's chief agent, the same id the team list uses. The legacy
    /// `main` id answers 404 on an owner install (10-27 real-app check).
    public static let agent = TeamMember.aux.id
    /// At most this many suggestions are shown at once.
    public static let suggestionLimit = 5

    @Published public private(set) var snapshot: MemorySnapshot?
    @Published public private(set) var loading = true
    /// The item being edited, and the text in the field.
    @Published public private(set) var editing: String?
    @Published public var draft = ""
    /// The item whose deletion waits for a second yes.
    @Published public private(set) var confirming: String?
    /// The last failure, and the row it belongs to.
    @Published public private(set) var problem: MemoryProblem?
    @Published public private(set) var problemItem: String?
    /// The row with a request in flight.
    @Published public private(set) var busy: String?

    private let client: MemoryClient

    public init(client: MemoryClient) { self.client = client }

    /// The suggestions, at most five.
    public var suggestions: [MemorySuggestion] {
        Array((snapshot?.suggestions ?? []).prefix(Self.suggestionLimit))
    }

    /// The sections to show: fixed order, all four. A section with no fact
    /// stays and says so in one line (MEM-EMPTY-STATE): an empty section is
    /// a fact about the owner, never a missing page.
    public var visibleSections: [MemorySection] {
        MemorySection.displayOrder
    }

    public func facts(in section: MemorySection) -> [MemoryFact] {
        snapshot?.groups[section.rawValue] ?? []
    }

    /// True when the section holds no fact of its own: the page then shows
    /// its one empty line, and hides it as soon as a fact lands.
    public func showsEmptyLine(in section: MemorySection) -> Bool {
        facts(in: section).isEmpty
    }

    // MARK: Reading

    public func load() async {
        if snapshot == nil { loading = true }
        do {
            snapshot = try await client.memorySnapshot(agent: Self.agent)
            problem = nil
            problemItem = nil
        } catch let error as AuxdError where error.isUnavailableRoute {
            fail(.unavailable, item: nil)
        } catch {
            if snapshot == nil {
                problem = MemoryProblem(error)
            } else {
                fail(MemoryProblem(error), item: nil)
            }
        }
        loading = false
    }

    // MARK: Editing

    public func beginEdit(_ fact: MemoryFact) {
        editing = fact.id
        draft = fact.text
        problem = nil
        problemItem = nil
    }

    public func cancelEdit() {
        editing = nil
        draft = ""
    }

    /// Save: the daemon supersedes the old fact, so the page reads it again.
    public func saveEdit() async {
        guard let id = editing else { return }
        let text = draft.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !text.isEmpty, text.count <= 2000 else { return fail(.invalidText, item: id) }
        busy = id
        defer { busy = nil }
        do {
            _ = try await client.updateMemory(agent: Self.agent, item: id, text: text)
            cancelEdit()
            await load()
        } catch {
            fail(MemoryProblem(error), item: id)
        }
    }

    // MARK: Forgetting

    /// The first click only asks; the second one forgets.
    public func askForget(_ fact: MemoryFact) {
        confirming = fact.id
        problem = nil
        problemItem = nil
    }

    public func cancelForget() { confirming = nil }

    public func forget(_ fact: MemoryFact) async {
        confirming = nil
        busy = fact.id
        defer { busy = nil }
        do {
            try await client.forgetMemory(agent: Self.agent, item: fact.id)
            remove(fact.id)
        } catch {
            fail(MemoryProblem(error), item: fact.id)
        }
    }

    // MARK: Suggestions

    /// "Remember" keeps the fact, "No" drops the suggestion. Both take the
    /// row away; the daemon decides where a kept fact belongs.
    public func decide(_ suggestion: MemorySuggestion, keep: Bool) async {
        busy = suggestion.id
        defer { busy = nil }
        do {
            if keep {
                _ = try await client.acceptMemorySuggestion(agent: Self.agent, suggestion: suggestion.id)
            } else {
                try await client.rejectMemorySuggestion(agent: Self.agent, suggestion: suggestion.id)
            }
            dropSuggestion(suggestion.id)
            await load()
        } catch {
            fail(MemoryProblem(error), item: suggestion.id)
        }
    }

    // MARK: Local state

    private func fail(_ problem: MemoryProblem, item: String?) {
        self.problem = problem
        problemItem = item
    }

    private func remove(_ id: String) {
        guard var snapshot else { return }
        for section in MemorySection.displayOrder {
            guard var items = snapshot.groups[section.rawValue] else { continue }
            let before = items.count
            items.removeAll { $0.id == id }
            guard items.count != before else { continue }
            snapshot.groups[section.rawValue] = items
            self.snapshot = snapshot
            return
        }
    }

    private func dropSuggestion(_ id: String) {
        guard var snapshot else { return }
        snapshot.suggestions.removeAll { $0.id == id }
        self.snapshot = snapshot
    }
}
