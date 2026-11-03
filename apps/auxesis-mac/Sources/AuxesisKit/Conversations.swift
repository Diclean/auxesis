import Foundation

public struct ConversationSummary: Decodable, Equatable, Identifiable {
    public let id: Int64
    public let title: String
    /// Last activity, UTC (`YYYY-MM-DD HH:MM:SS`).
    public let updatedAt: String

    public init(id: Int64, title: String, updatedAt: String) {
        self.id = id
        self.title = title
        self.updatedAt = updatedAt
    }

    enum CodingKeys: String, CodingKey {
        case id, title
        case updatedAt = "updated_at"
    }

    public var date: Date? { TimeText.parse(updatedAt) }
}

public enum ConversationList {
    public static let cap = 50

    public static func rows(_ loadable: Loadable<[ConversationSummary]>) -> [ConversationSummary] {
        guard case .loaded(let items) = loadable else { return [] }
        return ordered(items)
    }

    /// Newest activity first, id descending on a tie, unreadable dates last.
    public static func ordered(_ items: [ConversationSummary], cap: Int = ConversationList.cap) -> [ConversationSummary] {
        guard cap > 0 else { return [] }
        let sorted = items.sorted {
            ($0.date ?? .distantPast, $0.id) > ($1.date ?? .distantPast, $1.id)
        }
        return Array(sorted.prefix(cap))
    }

    public static func title(_ conversation: ConversationSummary, language: Language) -> String {
        let trimmed = conversation.title.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.isEmpty ? L10n.ui(.conversationUntitled, language) : trimmed
    }

    public static func timeLabel(
        _ conversation: ConversationSummary, now: Date = Date(), language: Language
    ) -> String? {
        conversation.date.map { TimeText.short($0, now: now, language: language) }
    }
}
