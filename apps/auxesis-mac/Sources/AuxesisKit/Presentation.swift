/// Presentation view-models: the small pure decisions the restyled views make
/// (rail search, row previews, day chips, quoted replies, clock). No SwiftUI
/// here, so `swift test` covers the behaviour without a window.
import Foundation

/// Local `HH:mm` formatting for message/approval timestamps.
public enum Clock {
    /// `HH:mm`, or "" when the timestamp is unknown — never a fabricated hour.
    public static func hhmm(_ ts: Int64) -> String {
        guard ts > 0 else { return "" }
        let formatter = DateFormatter()
        formatter.dateFormat = "HH:mm"
        return formatter.string(from: Date(timeIntervalSince1970: Double(ts) / 1000))
    }
}

/// State labels in one place (`Store.stateLabel` delegates here, the rail
/// preview uses the same words).
public enum AgentStateCopy {
    public static func label(_ state: AgentState, _ language: Language) -> String {
        switch state {
        case .idle: return L10n.t(.stateIdle, language)
        case .thinking: return L10n.t(.stateThinking, language)
        case .working: return L10n.t(.stateWorking, language)
        case .needsYou: return L10n.t(.stateNeedsYou, language)
        case .paused: return L10n.t(.statePaused, language)
        case .killed: return L10n.t(.stateKilled, language)
        }
    }
}

/// The required order for the per-agent detail pane.
public enum AgentProfileSection: CaseIterable, Hashable {
    case grants, brain, lastUse

    public static let contractOrder: [AgentProfileSection] = [.grants, .brain, .lastUse]
}

/// One line under an agent name in the rail: the real active status when auxd
/// reports one, otherwise the state ("working", "waiting for you", …). Never a
/// fabricated "last message".
public enum AgentRow {
    public static func preview(for agent: Agent, _ language: Language) -> String {
        let status = agent.status.trimmingCharacters(in: .whitespacesAndNewlines)
        if !status.isEmpty { return status }
        return AgentStateCopy.label(agent.state, language)
    }
}

/// Case- and accent-insensitive rail search over agent names.
public enum RailSearch {
    public static func filter(_ agents: [Agent], query: String) -> [Agent] {
        let needle = query.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !needle.isEmpty else { return agents }
        return agents.filter { agent in
            agent.name.range(of: needle, options: [.caseInsensitive, .diacriticInsensitive]) != nil
        }
    }
}

/// Day chips for the conversation ("Aujourd'hui", "Hier", then a short date).
public enum DayStamp {
    /// `nil` for unknown timestamps (never a fake date).
    public static func label(
        for ts: Int64,
        now: Date = Date(),
        _ language: Language,
        timeZone: TimeZone = .current,
        calendar: Calendar = .current
    ) -> String? {
        guard ts > 0 else { return nil }
        var cal = calendar
        cal.timeZone = timeZone
        let date = Date(timeIntervalSince1970: Double(ts) / 1000)
        if cal.isDate(date, inSameDayAs: now) {
            return L10n.t(.dayToday, language)
        }
        if let yesterday = cal.date(byAdding: .day, value: -1, to: now),
           cal.isDate(date, inSameDayAs: yesterday) {
            return L10n.t(.dayYesterday, language)
        }
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: language.localeIdentifier)
        formatter.timeZone = timeZone
        formatter.setLocalizedDateFormatFromTemplate("d MMM")
        return formatter.string(from: date)
    }
}

/// A conversation row: the message plus what the layout derives around it.
public struct ConversationRow: Equatable {
    public let message: ChatMessage
    /// Set on the first message of a new day (nil while the day is unknown).
    public let dayLabel: String?
    /// The owner message this agent reply directly follows, when there is one.
    public let quoted: ChatMessage?

    public init(message: ChatMessage, dayLabel: String?, quoted: ChatMessage?) {
        self.message = message
        self.dayLabel = dayLabel
        self.quoted = quoted
    }
}

public enum Conversation {
    /// Stamps day chips and quoted replies onto the message list. A quote is
    /// real data — the owner message immediately before an agent reply — and
    /// is shown only then (never invented).
    public static func rows(
        _ messages: [ChatMessage],
        now: Date = Date(),
        _ language: Language,
        timeZone: TimeZone = .current,
        calendar: Calendar = .current
    ) -> [ConversationRow] {
        var rows: [ConversationRow] = []
        var lastDay: String?
        for (index, message) in messages.enumerated() {
            let day = DayStamp.label(
                for: message.ts, now: now, language, timeZone: timeZone, calendar: calendar
            )
            let chip = day != nil && day != lastDay ? day : nil
            if let day { lastDay = day }
            rows.append(ConversationRow(
                message: message,
                dayLabel: chip,
                quoted: quote(for: message, at: index, in: messages)
            ))
        }
        return rows
    }

    /// The owner message an agent reply follows; `nil` for owner/tool/system
    /// messages, for the first message, or when the previous text is empty.
    public static func quote(
        for message: ChatMessage,
        at index: Int,
        in messages: [ChatMessage]
    ) -> ChatMessage? {
        guard index > 0, index < messages.count else { return nil }
        guard case .agent = message.author else { return nil }
        let previous = messages[index - 1]
        guard case .you = previous.author else { return nil }
        return previous.text.isEmpty ? nil : previous
    }
}
